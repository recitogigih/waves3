const mongoose = require('mongoose');
const bcrypt = require('bcrypt') //pasword hashing
const jwt = require('jsonwebtoken') //generate token
const SALT_I = 10;
require('dotenv').config(); //give access to secret key

const userSchema = mongoose.Schema({

    email: {
        type: String,
        required: true,
        trim: true,
        unique: 1
    },
    password: {
        type: String,
        required: true,
        minlength: 5
    },
    name: {
        type: String,
        required: true,
        maxlength: 100
    },
    lastname: {
        type: String,
        required: true,
        maxlength: 100
    },
    cart: {
        type: Array,
        default: []
    },
    history: {
        type: Array,
        default: []
    },
    role: {
        type: Number,
        default: 0
    },
    token: {
        type: String
    }
})

userSchema.pre('save', function (next) { //before do anything, do this.
    var user = this;

    if (user.isModified('password')){ //just hashing when it's modified
        bcrypt.genSalt(SALT_I, function (err, salt) {
            if (err) return next(err);
    
            bcrypt.hash(user.password, salt, function (err, hash) {
                if (err) return next(err);
                user.password = hash;
                next();
            })
        })
    } else {
        next()
    }   
})

userSchema.methods.comparePassword = function (candidatePassword,cb){
    bcrypt.compare(candidatePassword, this.password, function(err,isMatch){
        if(err) return cb(err);
        cb(null,isMatch)
    });
}

userSchema.methods.generateToken = function(cb ){
    var user = this;
    var token = jwt.sign(user._id.toHexString(),process.env.SECRET); //generate token + secret key

    user.token = token;  //update token
    user.save(function(err,user){
        if(err) return cb(err);
        cb(null,user)
    })
    // user.id + secretpassword 
}

userSchema.statics.findByToken = function(token,cb){
    var user = this;

    jwt.verify(token,process.env.SECRET,function(err,decode){
        user.findOne({"_id":decode,"token":token},function(err,user){
            if(err) return cb(err);
            cb(null,user)
        })
    })
}

const User = mongoose.model('User', userSchema);

module.exports = {
    User
}