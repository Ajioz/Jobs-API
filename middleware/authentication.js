require('dotenv').config();
const User = require('../models/User');
const jwt = require('jsonwebtoken');
const { UnauthenticatedError } = require('../errors');

const auth = async(req, res, next) => {

    const authHeader = req.headers.authorization
   
    if(!authHeader || !authHeader.startsWith('Bearer')){
        throw new UnauthenticatedError('Authentication invalid')
    }
    const token = authHeader.split(' ')[1];
    try {
        const verifyToken = jwt.verify(token, process.env.JWT_SECRET);

        //attach the user to the job routes
        //req.user = User.findById(verifyToken.id).select('-password')        // MEthod: 1

        req.user = { userId: verifyToken.userId, name: verifyToken.name }   // MEthod: 2
        next()

    } catch (error) {
        throw new UnauthenticatedError('Error in Authenticating user')
    }
    
}

module.exports = auth;