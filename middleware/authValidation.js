const validateRegistration = async (req, res, next) => {
	try {
		const { name, email, password, dateOfBirth } = req.body;
		const errors = [];
        if (!name) {
			errors.push("Please add name");
		}

		if (!email) {
			errors.push("Please add email");
		}

        if (
            !dateOfBirth ||
            typeof dateOfBirth !== 'object' ||
            !dateOfBirth.month ||
            !dateOfBirth.day ||
            !dateOfBirth.year
        ) {
            errors.push("Please provide a valid date of birth");
        }

		if (password.length < 8) {
			errors.push("Password should be minimum of eight characters");
		}

		if (errors.length > 0) {
			return res.status(400).json({ message: errors });
		}

		next();
	} catch (error) {
		return res.status(500).json({ message: error.message });
	}
};

module.exports = {validateRegistration}
	