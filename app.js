const express = require('express');
const connectDB = require('./config/db');
const authRoutes = require('./routes/authRoutes');
const dotenv = require('dotenv');

dotenv.config();

const app = express();
app.use(express.json());

connectDB();

app.use('/api/auth', authRoutes);

const PORT = process.env.PORT || 5000;



app.listen(PORT, () => console.log(`Server started on port ${PORT}`));
