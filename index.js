const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
require('dotenv').config();
const Stripe = require('stripe')(process.env.SECRET_KEY);


const app = express();
// app.use(cors());
app.use(
    cors({
      origin: 'http://localhost:3000', 
      
    })

  );
app.use(express.json({ limit: '10mb' }));
const bcrypt = require('bcrypt');
const saltRounds = 10; 



const PORT = 4000;

// Connect to MongoDB
mongoose.connect('mongodb://localhost:27017/your-database-name', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})

    .then(() => console.log('Connected to Database'))
    .catch((err) => console.error('Database connection error:', err));

// Define User Schema and Model
const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
    },

    email: {
        type: String,
        unique: true,
        required: true,
    },
    password: {
        type: String,
        required: true,
    },
    mobile: {
        type: String,
        required: true,
    },
    address: {
        type: String,
        required: true,
    },


});
const userModel = mongoose.model('user', userSchema);

// Define Product Schema and Model
const schemaProduct = mongoose.Schema({
    name: String,
    category: String,
    image: String,
    price: String,
    description: String,
});
const productModel = mongoose.model('product', schemaProduct);

const jwt = require('jsonwebtoken');

// Token generation
const generateToken = (user) => {
    return jwt.sign({ _id: user._id, email: user.email }, process.env.JWT_SECRET_KEY, { expiresIn: '1h' });
};

// Token verification middleware
const verifyToken = (req, res, next) => {
    const token = req.headers.authorization;

    if (!token) {
        return res.status(403).json({ message: 'Access denied. No token provided.' });
    }

    jwt.verify(token, process.env.JWT_SECRET_KEY, (err, decoded) => {
        if (err) {
            return res.status(401).json({ message: 'Invalid token.' });
        }
        req.user = decoded; // Store decoded user information in the request object
        next();
    });
};

module.exports = { generateToken, verifyToken };




// Default route
app.get('/', (req, res) => {
    res.send('Server is running');
});

// Signup
app.post('/signup', async (req, res) => {
    const { username, email, password, mobile, address } = req.body;

    try {
        const existingUser = await userModel.findOne({ email });

        if (existingUser) {
            return res.status(400).json({ message: 'Email already exists. Please use a different email.' });
        }

        // Hash the password before storing it
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        const newUser = new userModel({
            username,
            email,
            password: hashedPassword, // Store the hashed password in the database
            mobile,
            address,
        });

        const savedUser = await newUser.save();
        res.status(200).json({ message: 'User registered successfully', user: savedUser });
    } catch (error) {
        res.status(500).json({ message: 'Registration failed. Please try again later.', error: error.message });
    }
});

// Login
app.post('/login',async (req, res) => {
    try {

        const { email, password } = req.body;
    
        // Find the user by email
        const user = await userModel.findOne({ email });
    
        // If the user doesn't exist, return an error
        if (!user) {
          return res.status(401).json({ message: 'Invalid credentials' });
        }
    
       
        // Compare the provided password with the hashed password in the database
        const isPasswordValid = await bcrypt.compare(password, user.password);
    
        // If the passwords don't match, return an error
        if (!isPasswordValid) {
          return res.status(401).json({ message: 'Invalid credentials' });
        }
    
        // Create a JWT token with the user's ID
        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET_KEY, {
          expiresIn: '1h', // Token expiration time
        });
    
        // Send the token in the response
        res.status(200).json({ token });
      } catch (error) {
        console.error('Login error:', error);

        res.status(500).json({ message: 'Server error' });
      }
});




//Checkout
app.post('/create-checkout-session', async (req, res) => {
    const { products } = req.body;


  
    const lineItems = products.map(product => ({
        price_data: {
          currency: 'usd',
          product_data: {
            name: product.name,
          },
          unit_amount: product.price * 100,
        },
        quantity:1,
        
      }));
      
  
    try {
      const session = await Stripe.checkout.sessions.create({
        payment_method_types: ['card'],
        line_items: lineItems,
        mode: 'payment',
        success_url: 'http://localhost:3000/success',
        cancel_url: 'http://localhost:3000/cancel',
        
      });
  
      res.json({ id: session.id });
    } catch (error) {
      console.error('Error creating checkout session:', error);
      res.status(500).json({ error: 'Error creating checkout session' });
    }
  });
  

// Server listening on PORT
app.listen(PORT, () => console.log(`Server is running at port: ${PORT}`));
