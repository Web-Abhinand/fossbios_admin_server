const mongoose = require('mongoose');

const leaveRequestSchema = new mongoose.Schema({
    date: {
        type: String,
        required: true,
    },
    reason: {
        type: String,
        required: true,
    },
    leaveApproved: {
        type: Boolean,
        default: false,
    },
});

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
    rollno: {
        type: String,
    },
    role: {
        type: String,
    },
    approved: {
        type: Boolean,
        default: false
    },
    leaveRequests: [leaveRequestSchema],
});

module.exports = mongoose.model('User', userSchema);

