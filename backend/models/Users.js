const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    username: { type: String, unique: true, required: true },
    password: { type: String, required: true },  // This will store the hashed password
});

module.exports = mongoose.model('User', userSchema);
