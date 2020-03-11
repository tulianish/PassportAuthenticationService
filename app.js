var express 				= require('express'),
	mongoose 				= require('mongoose'),
	passport 				= require('passport'),
	bodyParser 				= require('body-parser'),
	User					= require('./models/user'),
	LocalStrategy 			= require('passport-local'),
	passportLocalMongoose 	= require('passport-local-mongoose'),
	flash = require('connect-flash');


mongoose.connect('mongodb://localhost/authwithsq')

var app = express();
app.set('view engine','ejs');

app.use(flash());
app.use(bodyParser.urlencoded({extended:true}));

app.use(require('express-session')({
	secret: 'Learning authentication',
	resave: false,
	saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());

passport.use('signup',new LocalStrategy({
	passReqToCallback : true
	},
	function(req,username,password,done)
	{
		console.log("Check if a username already exists");
		User.findOne({'username' : username},function(err,user){
			console.log("Username check started");
			//Error encountered on finding username in database before signing up
			if (err){
				console.log('Error in Signup' + err);
				return done(err);
			}
			if(user){
				console.log('User already exists');
				return done(null, false);
			}
			else{
				//No user found with matching username
				//Create new user
				console.log(req.body);
				var newUser = new User();
				newUser.username = username;
				newUser.password = newUser.generateHash(password);
				newUser.securityQuestion1 = req.body.securityQuestion1;
				newUser.answer1 = req.body.answer1;
				newUser.securityQuestion2 = req.body.securityQuestion2;
				newUser.answer2 = req.body.answer2;

				//Save the user to database
				newUser.save(function(err) {
					if(err){
						console.log('Error in saving User onto database : '+ err);
						throw err;
					}
					console.log('User Registration Successful');
					return done(null,newUser);
				});
			}
		});

	}
));


passport.use('login', new LocalStrategy({
        passReqToCallback : true // allows us to pass back the entire request to the callback
    },
    function(req, username, password, done) { // callback with email and password from our form
        // find a user whose email is the same as the forms email
        // we are checking to see if the user trying to login already exists
        User.findOne({ 'username' :  username }, function(err, user) {
            // if there are any errors, return the error before anything else
            if (err)
                return done(err);

            // if no user is found, return the message
            if (!user)
                return done(null, false, req.flash('loginMessage', 'No user found.')); // req.flash is the way to set flashdata using connect-flash

            // if the user is found but the password is wrong
            if (!user.validPassword(password))
                return done(null, false, req.flash('loginMessage', 'Oops! Wrong password.')); // create the loginMessage and save it to session as flashdata

            // all is well, return successful user
            else
				return done(null, user);
        });

    }));

passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

//=========
//ROUTES
//=========

app.get('/',function(req,res){
	res.render('home');

})

app.get('/secret',isLoggedIn,function(req,res){
	res.send('secret',{user:req.user.username});
})

app.get('/register',function(req,res){
	res.render('register');
})

app.post('/register',passport.authenticate('signup', {
	successRedirect : '/secret',
	failureRedirect : '/register',
	failureFlash : true
}));

app.get('/login',function(req,res){
	res.render('login');
})

app.post('/login', passport.authenticate('login', {
        successRedirect : '/secret', // redirect to the secure profile section
        failureRedirect : '/login', // redirect back to the signup page if there is an error
        failureFlash : true // allow flash messages
    }));

app.get('/logout',function(req,res){
	req.logout();
	res.redirect('/');
});

function isLoggedIn(req,res, next){
	if(req.isAuthenticated()){
		return next();
	}
	res.redirect('/login')
}

//===========
//LISTENER
//===========

app.listen(3000,function(){
	console.log('Server Started');
})