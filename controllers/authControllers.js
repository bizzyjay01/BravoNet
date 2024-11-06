const User = require("../models/user");
const Token = require("../models/Token");
const bcrypt = require("bcryptjs");
const sendEmail = require("../utils/sendEmail");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");

const generateOTP = () => {
	const otpCode = crypto.randomInt(100000, 999999).toString();

	return otpCode;
};

// Register User
exports.register = async (req, res) => {
	const { name, email, dateOfBirth, password, confirmPassword } = req.body;

	try {
		let user = await User.findOne({ email });

		if (password !== confirmPassword) {
			return res.status(400).json({ message: "Passwords do not match" });
		}
		if (user) {
			return res.status(400).json({ message: "User already exists" });
		}

		const hashedPassword = await bcrypt.hash(password, 10);
		user = new User({
			name,
			email,
			dateOfBirth,
			password: hashedPassword,
		});
		await user.save();
		res.status(201).json({ message: "Account Created successfully", user });
	} catch (error) {
		return res.status(500).json({ message: error.message });
	}
};

// Login User
exports.login = async (req, res) => {
	const { email, password } = req.body;

	try {
		const user = await User.findOne({ email });

		if (!user) {
			return res.status(404).json({ message: "User account not found" });
		}

		const isMatched = await bcrypt.compare(password, user.password);
		if (!isMatched) {
			return res.status(400).json({ message: "Incorrect password or email" });
		}

		const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
			expiresIn: "1h",
		});

		res.status(200).json({ message: "Login successful", token, user });
	} catch (error) {
		return res.status(500).json({ message: error.message });
	}
};

// Request Password Reset
exports.forgotPassword = async (req, res) => {
	const { email } = req.body;

	try {
		const user = await User.findOne({ email });
		if (!user) return res.status(404).json({ message: "User  not found" });

		// Generate OTP
		const otp = generateOTP();
		const saltRounds = 10;
		const hashedOtp = await bcrypt.hash(otp, saltRounds);

		user.otp = hashedOtp;
		user.otpExpires = Date.now() + 10 * 60 * 1000; // 10 minutes
		await user.save();

		// Send OTP via email
		await sendEmail(email, "Password Reset OTP", `Your OTP is ${otp}`);

		res.json({ message: "OTP sent to email" });
	} catch (error) {
		return res.status(500).json({ message: error.message });
	}
};

exports.verifyOtp = async (req, res) => {
	const { otp, email } = req.body;

	if (!otp || !email) {
		return res.status(400).json({ message: "OTP code and email are required" });
	}

	try {
		const user = await User.findOne({ email });
		if (!user) {
			return res.status(404).json({ message: "User not found" });
		}

		// Check if OTP exists and hasn't expired
		if (!user.otp || Date.now() > user.otpExpires) {
			return res.status(400).json({ message: "OTP is expired or invalid" });
		}

		// Compare the hashed OTP with the one entered by the user
		const isOtpValid = await bcrypt.compare(otp, user.otp);
		if (!isOtpValid) {
			return res.status(400).json({ message: "Invalid OTP code" });
		}

		// Save the user object after clearing OTP
		await user.save();

		res
			.status(200)
			.json({
				message: "OTP verified successfully, proceed to reset password",
			});
	} catch (error) {
		console.error(error);
		return res.status(500).json({ message: "Server error: " + error.message });
	}
};

// Reset Password
exports.resetPassword = async (req, res) => {
	const { email, otp, newPassword } = req.body;

	try {
		const user = await User.findOne({ email });
		// Check if OTP exists and hasn't expired
		if (!user.otp || Date.now() > user.otpExpires) {
			return res.status(400).json({ message: "OTP is expired or invalid" });
		}

		user.password = await bcrypt.hash(newPassword, 10);
		user.otp = null; // Clear OTP after use
		user.otpExpires = null; // Clear OTP expiration
		await user.save();
		res.json({ message: "Password reset successfully" });
	} catch (error) {
		return res.status(500).json({ message: error.message });
	}
};
