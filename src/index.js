require('dotenv').config();

const express = require('express');
const { authRouter } = require('./routes/auth.route.js');
const cors = require('cors');
const { userRouter } = require('./routes/user.route.js');
const { errorMiddleware } = require('./middlewares/errorMiddleware.js');
const cookieParser = require('cookie-parser');

const server = express();

server.use(express.json());
server.use(cookieParser());

server.use(
  cors({
    origin: process.env.CLIENT_HOST,
    credentials: true,
  }),
);
server.use(authRouter);
server.use('/users', userRouter);

server.use(errorMiddleware);

server.listen(process.env.PORT);
