const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
    },
    email: {
        type: String,
        required: true,
        unique: true,
    },
    dateOfBirth: {
        month: {
            type: String,
            required: [true, "Month of birth is required"],
        },
        day: {
            type: Number,
            required: true,
            min: 1,
            max: 31,
        },
        year: {
            type: Number,
            required: true,
            min: 1900,
            max: new Date().getFullYear(),
        },
    },
    password: {
        type: String,
        required: true,
    },
    otp: { type: String},
    
    otpExpires: { type: Date }
}, {
    timestamps: true,
});

module.exports = mongoose.model('User ', userSchema);