const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const adminRoutes = require('./adminRoutes');

const app = express();
app.use(cors());
app.use(express.json());

mongoose.connect('mongodb://127.0.0.1:27017/fossbiosuser', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});
const port = 8000;
app.listen(port, () => {
  console.log(`Admin Server is running on port: ${port}`);
});

// Use adminRoutes for admin panel endpoints
app.use('/admin', adminRoutes);