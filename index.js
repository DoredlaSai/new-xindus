// Import necessary libraries
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const bodyParser = require("body-parser");
const { Schema } = mongoose;

// Initialize Express app
const app = express();
app.use(bodyParser.json());

// Connect to MongoDB
mongoose.connect("mongodb://localhost:27017/wishlist_db", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});
mongoose.connection.on(
  "error",
  console.error.bind(console, "MongoDB connection error:")
);

// Define User schema
const userSchema = new Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});

// Define Wishlist Item schema
const wishlistItemSchema = new Schema({
  userId: { type: Schema.Types.ObjectId, ref: "User" },
  name: { type: String, required: true },
  description: String,
});

// Define User model
const User = mongoose.model("User", userSchema);

// Define Wishlist Item model
const WishlistItem = mongoose.model("WishlistItem", wishlistItemSchema);

// User authentication endpoint - Sign up
app.post("/api/signup", async (req, res) => {
  try {
    const { email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ email, password: hashedPassword });
    await user.save();
    res.status(201).send("User created successfully");
  } catch (error) {
    console.error(error);
    res.status(500).send("Error creating user");
  }
});

// User authentication endpoint - Log in
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).send("Invalid email or password");
    }
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).send("Invalid email or password");
    }
    const token = jwt.sign({ userId: user._id }, "secretkey");
    res.status(200).send({ token });
  } catch (error) {
    console.error(error);
    res.status(500).send("Error logging in");
  }
});

// Middleware to verify JWT token
function verifyToken(req, res, next) {
  const token = req.headers["authorization"];
  if (!token) {
    return res.status(403).send("Token is not provided");
  }
  jwt.verify(token, "secretkey", (err, decoded) => {
    if (err) {
      return res.status(401).send("Unauthorized access");
    }
    req.userId = decoded.userId;
    next();
  });
}

// Wishlist management endpoints
app.get("/api/wishlists", verifyToken, async (req, res) => {
  try {
    const userId = req.userId;
    const wishlistItems = await WishlistItem.find({ userId });
    res.status(200).json(wishlistItems);
  } catch (error) {
    console.error(error);
    res.status(500).send("Error retrieving wishlist");
  }
});

app.post("/api/wishlists", verifyToken, async (req, res) => {
  try {
    const userId = req.userId;
    const { name, description } = req.body;
    const wishlistItem = new WishlistItem({ userId, name, description });
    await wishlistItem.save();
    res.status(201).send("Wishlist item created successfully");
  } catch (error) {
    console.error(error);
    res.status(500).send("Error creating wishlist item");
  }
});

app.delete("/api/wishlists/:id", verifyToken, async (req, res) => {
  try {
    const userId = req.userId;
    const wishlistItemId = req.params.id;
    await WishlistItem.findOneAndDelete({ _id: wishlistItemId, userId });
    res.status(200).send("Wishlist item deleted successfully");
  } catch (error) {
    console.error(error);
    res.status(500).send("Error deleting wishlist item");
  }
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

module.exports = app;
