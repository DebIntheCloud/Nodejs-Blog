const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const User = require('./server/models/User');
 // adjust path if your model is elsewhere
require('dotenv').config(); // loads .env file

const uri = process.env.MONGODB_URI; // same env var you're using in app.js

mongoose.connect(uri)
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error(err));

const run = async () => {
  const hashedPassword = await bcrypt.hash('newpassword123', 10);

  const newUser = new User({
    username: 'admin',
    password: hashedPassword,
  });

  await newUser.save();
  console.log('✅ Admin user created');
  mongoose.disconnect();
};

run();
