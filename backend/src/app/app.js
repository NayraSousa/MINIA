const express = require('express')
const cors = require('cors')

const userRoutes = require("./routes/UserRoute")
const authRoutes = require("./routes/AuthRoute")
const jobRouter = require('./routes/JobRoute')
const jobApplicationRouter = require('./routes/JobApplicationRoute')
const candidateRouter = require('./routes/CandidateRoute')

const app = express()

app.use(cors())
app.use(express.json())

app.use(userRoutes)
app.use(authRoutes)
app.use(jobRouter)
app.use(jobApplicationRouter)
app.use(candidateRouter)

module.exports = app