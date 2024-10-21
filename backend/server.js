const express = require('express');  // Importing express framework
const cors = require('cors');  // Import CORS package
const app = express();  // Initializing an Express app
const bcrypt = require('bcrypt');
const mongoose = require('mongoose');
const Users = require('./models/Users');  // Import your User model

app.use(cors());  // Enable CORS for all routes

mongoose.connect('mongodb://localhost:27017/authentication_demo', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
});

app.post('/api/register', async (req,res) => {

    const {username,password,confirmPassword} = req.body;

    if (password != confirmPassword){
        return res.status(400).json({ message: "Passwords do not match." })
    }

    const existingUser = await Users.findOne({ username });
    if (existingUser) {
        return res.status(400).json({ message: "Username is taken" })
    }

    // Hash the password
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    const newUser = new Users({
        username,
        password: hashedPassword,
    });

    await newUser.save()
    res.status(201).json({ message: "User registered successfully." });

})

let count = 0;

// Define a basic route for your API
app.get("/", (req, res) => {
    res.send("Hello, this is your basic backend!");
});

app.get("/api/count", (req,res) => {
    res.json({ count });
});

app.post("/api/increment", (req,res) => {
    count += 1;
    res.json({ count });
});

// Example route that returns some data
app.get('/api/data', (req, res) => {
    res.json({ message: "Hello from the Express backend!"});
});




// Start the server on port 5000
app.listen(5000, () => {
    console.log("Server is running on http://localhost:5000");
});
