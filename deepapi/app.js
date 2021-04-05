const express = require('express');
const bodyParser = require('body-parser');
const app = express();

const authRoutes = require('./routes/auth.js');

app.use(bodyParser.json());

app.use('/', authRoutes);

app.listen(3004, () => {
  console.log("Server running on port 3004.");
});
