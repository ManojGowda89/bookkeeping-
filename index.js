const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const i18n = require('i18n');
const multer = require('multer');
const dotenv = require('dotenv');

dotenv.config();
const app = express();
app.use(express.json());

// Initialize i18n for multilingual support
i18n.configure({
    locales: ['en', 'hi'],
    directory: __dirname + '/locales',
    defaultLocale: 'en',
    queryParameter: 'lang'
});
app.use(i18n.init);

// MongoDB models
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true });

const userSchema = new mongoose.Schema({
    name: String,
    email: { type: String, unique: true },
    password: String,
    role: { type: String, enum: ['author', 'borrower'] },
    language: { type: String, enum: ['en', 'hi'], default: 'en' }
});
const User = mongoose.model('User', userSchema);

const bookSchema = new mongoose.Schema({
    title: String,
    authorId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    libraryId: { type: mongoose.Schema.Types.ObjectId, ref: 'Library' },
    borrowerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
    coverImage: String // Store image URL as a string
});
const Book = mongoose.model('Book', bookSchema);

const librarySchema = new mongoose.Schema({
    name: String,
    location: String,
    books: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Book' }]
});
const Library = mongoose.model('Library', librarySchema);

// Middleware for JWT authentication
const auth = (req, res, next) => {
    const token = req.headers.authorization;
    if (!token) return res.status(401).json({ message: res.__('Unauthorized') });
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: res.__('Forbidden') });
        req.user = user;
        next();
    });
};

// Role-based access control
const roleAuth = (roles) => (req, res, next) => {
    if (!roles.includes(req.user.role)) {
        return res.status(403).json({ message: res.__('Forbidden') });
    }
    next();
};

// File upload setup
const upload = multer({ storage: multer.memoryStorage() });

// Routes
// User Registration
app.post('/api/users/register', async (req, res) => {
    try {
        const { name, email, password, role, language } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({ name, email, password: hashedPassword, role, language });
        await user.save();
        res.status(201).json({ message: res.__('User registered successfully') });
    } catch (error) {
        res.status(500).json({ message: res.__('User registration failed') });
    }
});

// User Login
app.post('/api/users/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(400).json({ message: res.__('Invalid credentials') });
        }
        const token = jwt.sign({ id: user._id, role: user.role, language: user.language }, process.env.JWT_SECRET);
        res.json({ token });
    } catch (error) {
        res.status(500).json({ message: res.__('Login failed') });
    }
});

// Book Routes
app.get('/api/books', auth, async (req, res) => {
    const books = await Book.find().populate('authorId libraryId borrowerId');
    res.json(books);
});

app.get('/api/books/:id', auth, async (req, res) => {
    const book = await Book.findById(req.params.id).populate('authorId libraryId borrowerId');
    if (!book) return res.status(404).json({ message: res.__('Book not found') });
    res.json(book);
});

app.post('/api/books', auth, roleAuth(['author']), upload.single('coverImage'), async (req, res) => {
    try {
        const coverImage = req.body.coverImage; // Here you can directly use the URL or path of the image
        const book = new Book({ ...req.body, coverImage, authorId: req.user.id });
        await book.save();
        res.status(201).json({ message: res.__('Book created successfully') });
    } catch (error) {
        res.status(500).json({ message: res.__('Failed to create book') });
    }
});

app.put('/api/books/:id', auth, async (req, res) => {
    const book = await Book.findByIdAndUpdate(req.params.id, req.body, { new: true });
    if (!book) return res.status(404).json({ message: res.__('Book not found') });
    res.json(book);
});

app.delete('/api/books/:id', auth, roleAuth(['admin']), async (req, res) => {
    await Book.findByIdAndDelete(req.params.id);
    res.json({ message: res.__('Book deleted') });
});

// Borrowing
app.post('/api/borrow', auth, async (req, res) => {
    const book = await Book.findById(req.body.bookId);
    if (!book || book.borrowerId) return res.status(400).json({ message: res.__('Book already borrowed') });
    book.borrowerId = req.user.id;
    await book.save();
    res.json({ message: res.__('Book borrowed successfully') });
});

app.put('/api/return/:id', auth, async (req, res) => {
    const book = await Book.findById(req.params.id);
    if (!book || book.borrowerId.toString() !== req.user.id) {
        return res.status(400).json({ message: res.__('You did not borrow this book') });
    }
    book.borrowerId = null;
    await book.save();
    res.json({ message: res.__('Book returned successfully') });
});

// Library Routes
app.get('/api/libraries', auth, async (req, res) => {
    const libraries = await Library.find().populate({ path: 'books', populate: { path: 'borrowerId' } });
    res.json(libraries);
});

app.get('/api/libraries/:id', auth, async (req, res) => {
    const library = await Library.findById(req.params.id).populate({ path: 'books', populate: { path: 'borrowerId' } });
    if (!library) return res.status(404).json({ message: res.__('Library not found') });
    res.json(library);
});

app.post('/api/libraries', auth, roleAuth(['admin']), async (req, res) => {
    const library = new Library(req.body);
    await library.save();
    res.status(201).json({ message: res.__('Library created successfully') });
});

app.put('/api/libraries/:id', auth, roleAuth(['admin']), async (req, res) => {
    const library = await Library.findByIdAndUpdate(req.params.id, req.body, { new: true });
    if (!library) return res.status(404).json({ message: res.__('Library not found') });
    res.json(library);
});

app.delete('/api/libraries/:id', auth, roleAuth(['admin']), async (req, res) => {
    await Library.findByIdAndDelete(req.params.id);
    res.json({ message: res.__('Library deleted') });
});

app.listen(process.env.PORT || 3000, () => {
    console.log('Server running on port', process.env.PORT || 3000);
});
