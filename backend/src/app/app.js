const express = require('express')
const cors = require('cors')

const userRoutes = require("./routes/UserRoute")
const authRoutes = require("./routes/AuthRoute")
const jobRoutes = require("./routes/JobRoute")
const jobApplicationRoutes = require("./routes/JobApplicationRoute")
const candidateRoutes = require("./routes/CandidateRoute")
const recruiterRoutes = require("./routes/RecruiterRoute")
const companyRoutes = require("./routes/CompanyRoute")
const analysisRouter = require("./routes/ResumeAnalysisRouter")

const app = express()

app.use(cors())
app.use(express.json())

app.use(userRoutes)
app.use(authRoutes)
app.use(jobRoutes)
app.use(jobApplicationRoutes)
app.use(candidateRoutes)
app.use(recruiterRoutes)
app.use(companyRoutes)
app.use(analysisRouter)


module.exports = app