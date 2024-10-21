const express = require('express')
const app = express()
const cors = require('cors');
app.use(cors());
app.get("/api", (req,res) =>
    res.json({ "testing": ["one","two","three"] })
)
app.listen(5000, () => { console.log("Server has started" )})