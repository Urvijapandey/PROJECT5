const express = require('express');
const userRoutes = require('./routes/user');

const app = express();
app.use(express.json());
app.use('/api', userRoutes);

app.listen(3000, () => console.log('SafeVault running on http://localhost:3000'));
