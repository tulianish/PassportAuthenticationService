var mongoose =  require("mongoose");
var PassportLocalMongoose = require("passport-local-mongoose");
var bcrypt   = require('bcrypt-nodejs');

var UserSchema = new mongoose.Schema({
	userName: String,
	password:String,
	securityQuestion1: String,
	answer1: String,
	securityQuestion2: String,
	answer2: String
});

UserSchema.plugin(PassportLocalMongoose);

// methods ======================

// generating a hash
UserSchema.methods.generateHash = function(password) {
    return bcrypt.hashSync(password, bcrypt.genSaltSync(8), null);
};

// checking if password is valid
UserSchema.methods.validPassword = function(candidatePassword) {
    if(this.password != null) {
        return bcrypt.compareSync(candidatePassword, this.password);
    } else {
        return false;
    }
};


module.exports = mongoose.model("User", UserSchema);