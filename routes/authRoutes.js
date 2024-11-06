const express = require('express');
const { register, login, forgotPassword, resetPassword, verifyOtp } = require('../controllers/authControllers');
// const { body, validationResult } = require('express-validator');
const { validateRegistration } = require('../middleware/authValidation');

const router = express.Router();

router.post('/register',validateRegistration, register);

router.post('/login', login);

router.post('/forgot-password', forgotPassword);
router.post('/verify-otp', verifyOtp)
router.post('/reset-password', resetPassword);


module.exports = router;