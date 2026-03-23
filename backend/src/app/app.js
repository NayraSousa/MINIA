const express = require('express')
const cors = require('cors')

const userRoutes = require("./routes/UserRoute")
const authRoutes = require("./routes/AuthRoute")

const app = express()

app.use(cors())
app.use(express.json())

app.use(userRoutes)
app.use(authRoutes)

module.exports = app