var createError = require('http-errors');
var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');
var mongoose = require('mongoose');
require('./models');
var bcrypt = require('bcrypt');
var expressSession = require('express-session');
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var dotenv = require('dotenv');
dotenv.config()
  // Set your secret key. Remember to switch to your live secret key in production!
// See your keys here: https://dashboard.stripe.com/account/apikeys
const Stripe = require('stripe');
const stripe = Stripe(process.env.STRIPE_SECRET_KEY);


var User = mongoose.model('User')

mongoose.connect('mongodb://' + process.env.MONGO_USERNAME + ':' + process.env.MONGO_PASSWORD + '@localhost:27017/prototype_db_1', { useNewUrlParser: true, useUnifiedTopology: true });


var app = express();

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

// Use body-parser to retrieve the raw body as a buffer
const bodyParser = require('body-parser');

const fulfillOrder = (session) => {
  // TODO: fill me in
  console.log("Fulfilling order", session);
  User.findOne({
    email: session.customer_email
  }, function(err,user) {
    if(user) {
      user.subscriptionActive = true;
      user.subscriptionId = session.subscription;
      user.customerId = session.customer;
      user.save();
    }
  })
}

app.post('/pay-success', bodyParser.raw({type: 'application/json'}), (request, response) => {
  const payload = request.body;
  const sig = request.headers['stripe-signature'];

  let event;

  try {
    event = stripe.webhooks.constructEvent(payload, sig, process.env.ENDPOINT_SECRET);
  } catch (err) {
    return response.status(400).send(`Webhook Error: ${err.message}`);
  }

  // Handle the checkout.session.completed event
  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    console.log(session)
    // Fulfill the purchase...
    
    fulfillOrder(session);
  }

  response.status(200);
});
//app.listen(4242, () => console.log('Running on port 4242'));

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
app.use(expressSession({
  secret: process.env.EXPRESS_SESSION_SECRET,
  resave: true,
    saveUninitialized: true
}));
app.use(passport.initialize());
app.use(passport.session());

passport.use(new LocalStrategy({
  usernameField: 'email',
  passwordField: 'password'
}, function(email, password, next) {
  User.findOne({
    email:email
  }, function(err, user) {
    if (err) return next(err);
    if(!user || !bcrypt.compareSync(password, user.passwordHash)) {
      return next({message: 'Email or password incorrect'})
    }
    next(null, user);
  })
}));

passport.use('signup_local', new LocalStrategy({
  usernameField: 'email',
  passwordField: 'password'
}, function(email, password, next) {
  User.findOne({
    email: email
  }, function(err, user){
    if(err) return next(err);
    if(user) return next({message: "User already exists"});
    let newUser = new User({
      email: email,
      passwordHash: bcrypt.hashSync(password, 10)
    });
    newUser.save(function(err) {
      next(err, newUser);
    })
  })
}));

passport.serializeUser(function(user, next){
  next(null, user._id);
})
passport.deserializeUser(function(id, next){
  User.findById(id, function(err,user) {
    next(err, user);
  })
})

app.get('/', function(req,res,next) {
  res.render('index',{title: "SaaS Prototype"})
})
app.get('/billing', function(req,res,next) {
  stripe.checkout.sessions.create({
    mode: "subscription",
    customer_email: req.user.email,
    payment_method_types: ['card'],
    line_items: [
      {
        price: process.env.STRIPE_PRICE_PLAN,
        quantity: 1,
      }
    ],
    success_url: 'http://localhost:3000/billing?session_id={CHECKOUT_SESSION_ID}',
    cancel_url: 'http://localhost:3000/billing',
  }, function(err, session){
    if (err) return next(err);
    res.render('billing', {STRIPE_PUBLIC_KEY: process.env.STRIPE_PUBLIC_KEY, sessionId: session.id, subscriptionActive: req.user.subscriptionActive})
  })
})

app.get('/logout', function(req,res,next) {
  req.logout();
  res.redirect('/');
})
app.get('/main', function(req,res,next) {
  res.render('main')
})
app.post('/login', 
  passport.authenticate('local', { failureRedirect: '/login_page' }),
  function(req, res) {
    res.redirect('/main');
  });
app.get('/login_page', function(req,res,next) {
  res.render('login_page')
})
app.post('/signup', 
  passport.authenticate('signup_local', { failureRedirect: '/' }),
  function(req, res) {
    res.redirect('/main');
  });



app.post("/create-checkout-session", async (req, res) => {
  const { priceId } = req.body;

  // See https://stripe.com/docs/api/checkout/sessions/create
  // for additional parameters to pass.
  try {
    const session = await stripe.checkout.sessions.create({
      mode: "subscription",
      payment_method_types: ["card"],
      line_items: [
        {
          price: priceId,
          // For metered billing, do not pass quantity
          quantity: 1,
        },
      ],
      // {CHECKOUT_SESSION_ID} is a string literal; do not change it!
      // the actual Session ID is returned in the query parameter when your customer
      // is redirected to the success page.
      success_url: 'http://localhost:3000/billing?session_id={CHECKOUT_SESSION_ID}',
    cancel_url: 'http://localhost:3000/billing',
    });

    res.send({
      sessionId: session.id,
    });
  } catch (e) {
    res.status(400);
    return res.send({
      error: {
        message: e.message,
      }
    });
  }
});

  

  app.post('/create-customer-portal-session', async (req, res) => {
    // Authenticate your user.
  
    const session = await stripe.billingPortal.sessions.create({
      customer: res.id,
      return_url: 'http://localhost:3000',
    });
  
    res.redirect(session.url);
  });

  

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  next(createError(404));
});

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});

module.exports = app;
