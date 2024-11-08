
```markdown
# Bookkeeping Service API

This is a simple bookkeeping service API built with Express.js. It manages books, users, and libraries, allowing users to register, log in, borrow books, and manage library inventories.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Environment Variables](#environment-variables)
- [API Endpoints](#api-endpoints)
- [Usage Examples](#usage-examples)
- [License](#license)

## Features

- User registration and authentication
- Manage books with detailed information
- Borrow and return books
- Manage libraries and their inventories
- Multilingual support for error/success messages (English and Hindi)

## Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/YOUR_USERNAME/bookkeeping-service.git
   cd bookkeeping-service
   ```

2. **Install dependencies**:
   ```bash
   npm install
   ```

3. **Start the server**:
   ```bash
   npm run dev
   ```
   The server will run on `http://localhost:5000`.

## Environment Variables

Create a `.env` file in the root directory of the project and add the following variables:

```plaintext
MONGO_URI=<Your MongoDB URI>
JWT_SECRET=<Your JWT Secret Key>
PORT=5000
```

- `MONGO_URI`: The URI for your MongoDB database.
- `JWT_SECRET`: A secret key used for signing JWT tokens.
- `PORT`: The port on which the server will run (default is `5000`).

## API Endpoints

### User Endpoints

- **Register User**: `POST /api/users/register`
- **Login User**: `POST /api/users/login`

### Book Endpoints

- **Retrieve All Books**: `GET /api/books`
- **Retrieve a Specific Book**: `GET /api/books/:id`
- **Create a New Book**: `POST /api/books`
- **Update a Book**: `PUT /api/books/:id`
- **Delete a Book**: `DELETE /api/books/:id`

### Borrowing Endpoints

- **Borrow a Book**: `POST /api/borrow`
- **Return a Book**: `PUT /api/return/:id`

### Library Endpoints

- **Retrieve All Libraries**: `GET /api/libraries`
- **Retrieve a Specific Library**: `GET /api/libraries/:id`
- **Create a New Library**: `POST /api/libraries`
- **Update a Library**: `PUT /api/libraries/:id`
- **Delete a Library**: `DELETE /api/libraries/:id`

### Library Inventory Endpoints

- **Retrieve Inventory of a Specific Library**: `GET /api/libraries/:id/inventory`
- **Add a Book to Library Inventory**: `POST /api/libraries/:id/inventory`
- **Remove a Book from Library Inventory**: `DELETE /api/libraries/:id/inventory/:bookId`

## Usage Examples

### User Registration

```bash
curl -X POST http://localhost:5000/api/users/register \
-H "Content-Type: application/json" \
-d '{"username": "author1", "password": "securePassword", "role": "author"}'
```

### User Login

```bash
curl -X POST http://localhost:5000/api/users/login \
-H "Content-Type: application/json" \
-d '{"username": "author1", "password": "securePassword"}'
```

### Retrieve All Books

```bash
curl -X GET http://localhost:5000/api/books \
-H "Authorization: Bearer YOUR_JWT_TOKEN"
```

### Create a New Book

```bash
curl -X POST http://localhost:5000/api/books \
-H "Content-Type: application/json" \
-H "Authorization: Bearer YOUR_JWT_TOKEN" \
-d '{"title": "New Book Title", "author": "AUTHOR_ID", "library": "LIBRARY_ID", "image": "http://image.url", "borrower": null}'
```

### Borrow a Book

```bash
curl -X POST http://localhost:5000/api/borrow \
-H "Content-Type: application/json" \
-H "Authorization: Bearer YOUR_JWT_TOKEN" \
-d '{"bookId": "BOOK_ID", "userId": "BORROWER_ID"}'
```

### Return a Book

```bash
curl -X PUT http://localhost:5000/api/return/BOOK_ID \
-H "Authorization: Bearer YOUR_JWT_TOKEN"
```

### Notes:
- Replace `YOUR_JWT_TOKEN` with the actual JWT obtained after logging in.
- Replace `BOOK_ID`, `AUTHOR_ID`, `LIBRARY_ID`, and `BORROWER_ID` with the actual IDs relevant to your database.
- Ensure your server is running locally on the specified port (5000 in this case).

