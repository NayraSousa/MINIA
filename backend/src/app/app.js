const express = require('express')
const cors = require('cors')

const userRoutes = require("./routes/UserRoute")

const app = express()

app.use(cors())
app.use(express.json())

app.use(userRoutes)

module.exports = app