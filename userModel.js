const mongoose = require('mongoose');


const userSchema = new mongoose.Schema({
    name: {
        type: String,
    },
    email: {
        type: String,
    },
    password: {
        type: String,
    },
    roll: {
        type: String,
    },
    role: {
        type: String,
    },
    club: {
        type: String,
    },
    approved: {
        type: Boolean,
        default: false,
    }
});


module.exports = mongoose.model('User', userSchema);

