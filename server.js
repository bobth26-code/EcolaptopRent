
require("dotenv").config();

const express = require("express");
const mysql = require("mysql2");

const bcrypt = require("bcrypt");
const session = require("express-session");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const path = require("path");






/* ================= CREATE APP ================= */
const app = express();

/* ================= CONFIG ================= */
const PORT = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || "ecommerce_secret";

/* ================= MIDDLEWARE ================= */
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.use(cors({
    origin: process.env.FRONTEND_URL || "http://localhost:3000",
    credentials: true
}));




// Admin Middleware
function isAdmin(req, res, next) {
    try {
        if (!req.session || !req.session.user) {
            return res.status(401).json({
                success: false,
                message: "Not logged in"
            });
        }

        if (req.session.user.role !== "admin") {
            return res.status(403).json({
                success: false,
                message: "Access denied"
            });
        }

        next();

    } catch (error) {
        console.error("Admin middleware error:", error);
        return res.status(500).json({
            success: false,
            message: "Server error"
        });
    }
}

// Seller Middleware


function isSeller(req, res, next) {

    try {

        if (!req.session || !req.session.user) {
            return res.status(401).json({
                success: false,
                message: "Not logged in"
            });
        }

        if (req.session.user.role !== "seller") {
            return res.status(403).json({
                success: false,
                message: "Access denied"
            });
        }

        next();

    } catch (error) {
        console.error("Seller middleware error:", error);
        return res.status(500).json({
            success: false,
            message: "Server error"
        });
    }
}

function isUser(req, res, next) {

    if (!req.session || !req.session.user) {
        return res.status(401).json({
            success: false,
            message: "Login required"
        });
    }

    if (req.session.user.role !== "user") {
        return res.status(403).json({
            success: false,
            message: "User access only"
        });
    }

    next();
}


/* ================= SESSION ================= */
app.set("trust proxy", 1);

app.use(session({
    name: "ecommerce.sid",
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: true,
        sameSite: "none",
        maxAge: 1000 * 60 * 60 * 24
    }
}));

/* ================= STATIC FILES ================= */
app.use(express.static(path.join(__dirname, "public")));

/* ================= DATABASE ================= */
const db = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME,
    connectionLimit: 10,
    ssl: {
        rejectUnauthorized: false
    }
});
db.getConnection((err, conn) => {
    if (err) {
        console.error("❌ DB CONNECTION ERROR:", err.message);
        process.exit(1);
    }
    console.log("✅ MySQL Connected");
    conn.release();
});

/* ================= REGISTER ================= */
app.post("/register", async (req, res) => {
    const { role, full_name, email, mobile, password } = req.body;

    if (!role || !full_name || !email || !mobile || !password) {
        return res.status(400).json({ success:false, error:"All fields required" });
    }

    if (!["user","seller","admin"].includes(role)) {
        return res.status(400).json({ success:false, error:"Invalid role" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    db.query(
        "SELECT id FROM users WHERE email=? OR mobile=?",
        [email, mobile],
        (err, rows) => {
            if (rows.length > 0) {
                return res.status(409).json({ success:false, error:"Already registered" });
            }

            db.query(
                `INSERT INTO users (role, full_name, email, mobile, password)
                 VALUES (?,?,?,?,?)`,
                [role, full_name, email, mobile, hashedPassword],
                (err, result) => {
                    if (err) {
                        return res.status(500).json({ success:false, error:"Insert failed" });
                    }

                    req.session.user = {
                        id: result.insertId,
                        role,
                        full_name,
                        email
                    };

                    res.json({
                        success: true,
                        redirect: role === "seller"
                            ? "/seller_dashboard.html"
                            : "/homepage.html"
                    });
                }
            );
        }
    );
});

/* ================= LOGIN ================= */
app.post("/login", (req, res) => {
    const { email, password } = req.body;

    db.query(
        "SELECT * FROM users WHERE email=? LIMIT 1",
        [email],
        async (err, rows) => {
            if (rows.length === 0) {
                return res.status(401).json({ success:false });
            }

            const user = rows[0];
            const match = await bcrypt.compare(password, user.password);
            if (!match) {
                return res.status(401).json({ success:false });
            }

            req.session.user = {
                id: user.id,
                role: user.role,
                full_name: user.full_name,
                email: user.email,
                mobile:user.mobile
            };






            let redirect = "/homepage.html";
            if (user.role === "seller") redirect = "/seller_dashboard.html";
            if (user.role === "admin") redirect = "/admin_dashboard.html";

            res.json({ success:true, redirect });
        }
    );
});


/* ================= OTP MANAGEMENT ================= */
const otpStore = {}; // Store OTPs with expiry: { email: { code: "123456", expiry: timestamp } }

function generateOTP() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

// Request OTP
app.post("/request-otp", (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ success: false, error: "Email required" });
    }

    // Check if email exists in database
    db.query(
        "SELECT id, role FROM users WHERE email=? LIMIT 1",
        [email],
        (err, rows) => {
            if (rows.length === 0) {
                return res.status(404).json({ success: false, error: "Email not registered" });
            }

            const otp = generateOTP();
            const expiry = Date.now() + 10 * 60 * 1000; // 10 minutes

            otpStore[email] = { code: otp, expiry, role: rows[0].role };

            console.log(`🔐 OTP for ${email}: ${otp}`); // Log for testing
            // TODO: Send OTP via email using nodemailer or similar service

            res.json({ success: true, message: "OTP sent to email" });
        }
    );
});

// Verify OTP
app.post("/verify-otp", (req, res) => {
    const { email, otp } = req.body;

    if (!email || !otp) {
        return res.status(400).json({ success: false, error: "Email and OTP required" });
    }

    const storedOtp = otpStore[email];

    if (!storedOtp) {
        return res.status(400).json({ success: false, error: "No OTP found. Request a new one." });
    }

    if (Date.now() > storedOtp.expiry) {
        delete otpStore[email];
        return res.status(400).json({ success: false, error: "OTP expired" });
    }

    if (storedOtp.code !== otp) {
        return res.status(400).json({ success: false, error: "Invalid OTP" });
    }

    // OTP verified, clean up
    delete otpStore[email];

    res.json({ 
        success: true, 
        message: "OTP verified",
        role: storedOtp.role 
    });
});



// ================= ADMIN GET USERS & SELLERS =================


app.get("/admin/users", isAdmin, (req, res) => {

    try {

        const sql = `
            SELECT id, role, full_name, email, mobile, created_at
            FROM users
            WHERE role IN ('user','seller')
            ORDER BY created_at DESC
        `;

        db.query(sql, (err, results) => {

            if (err) {
                console.error("Database Error:", err);
                return res.status(500).json({
                    success: false,
                    message: "Database error"
                });
            }

            const users = results.filter(u => u.role === "user");
            const sellers = results.filter(u => u.role === "seller");

            res.json({
                success: true,
                users,
                sellers
            });

        });

    } catch (error) {
        console.error("Server Error:", error);
        res.status(500).json({
            success: false,
            message: "Server error"
        });
    }

});


// ==========   Keep Delete Route    ========//


app.delete("/admin/user/:id", isAdmin, (req, res) => {

    try {

        const userId = req.params.id;

        if (!userId) {
            return res.status(400).json({
                success: false,
                message: "Invalid ID"
            });
        }

        const sql = "DELETE FROM users WHERE id = ?";

        db.query(sql, [userId], (err, result) => {

            if (err) {
                console.error("Delete Error:", err);
                return res.status(500).json({
                    success: false,
                    message: "Delete failed"
                });
            }

            res.json({
                success: true,
                message: "User deleted successfully"
            });

        });

    } catch (error) {
        console.error("Server Crash:", error);
        res.status(500).json({
            success: false,
            message: "Server error"
        });
    }

});







// *========= user address =======*//




app.get("/user/address", (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ loggedIn: false });
    }

    const userId = req.session.user.id;

    const sql = `
        SELECT address1, address2, address3
        FROM users
        WHERE id = ?
    `;

    db.query(sql, [userId], (err, result) => {
        if (err) {
            return res.status(500).json({
                success: false,
                message: "Database error"
            });
        }

        res.json({
            success: true,
            address1: result[0]?.address1 || null,
            address2: result[0]?.address2 || null,
            address3: result[0]?.address3 || null
        });
    });
});









app.post("/user/address/:slot", (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ message: "Unauthorized" });
    }

    const { slot } = req.params;
    const { address } = req.body;
    const userId = req.session.user.id;

    const allowed = ["address1", "address2", "address3"];
    if (!allowed.includes(slot)) {
        return res.status(400).json({ message: "Invalid address slot" });
    }

    if (!address || address.trim().length < 5) {
        return res.status(400).json({ message: "Invalid address" });
    }

    const sql = `
        UPDATE users 
        SET ${slot} = ?
        WHERE id = ?
    `;

    db.query(sql, [address, userId], err => {
        if (err) {
            return res.status(500).json({ message: "Database error" });
        }

        res.json({
            success: true,
            message: `${slot} updated successfully`
        });
    });
});











app.delete("/user/address/:slot", (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ message: "Unauthorized" });
    }

    const { slot } = req.params;
    const userId = req.session.user.id;

    const allowed = ["address1", "address2", "address3"];
    if (!allowed.includes(slot)) {
        return res.status(400).json({ message: "Invalid address slot" });
    }

    const sql = `
        UPDATE users 
        SET ${slot} = NULL
        WHERE id = ?
    `;

    db.query(sql, [userId], err => {
        if (err) {
            return res.status(500).json({ message: "Database error" });
        }

        res.json({ success: true });
    });
});













/* ================= SELLER ADD PRODUCT ================= */
app.post("/seller/product", (req, res) => {

    if (!req.session.user || req.session.user.role !== "seller") {
        return res.status(403).json({ success:false });
    }

    const { name, description, category, price, stock, image } = req.body;

    console.log("SESSION:", req.session.user);
    console.log("BODY:", req.body);

    if (!name || !category || !price) {
        return res.status(400).json({
            success:false,
            error:"Missing required fields"
        });
    }

    const sql = `
        INSERT INTO products
        (seller_id, name, description, category, price, stock, image)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    `;

    db.query(sql, [
        req.session.user.id,
        name,
        description || "",
        category,
        price,
        stock || 1,
        image || ""
    ], (err) => {

        if (err) {
            console.error("INSERT ERROR:", err);
            return res.status(500).json({
                success:false,
                error: err.message
            });
        }

        res.json({ success:true });

    });
});

/* ================= SELLER VIEW PRODUCTS ================= */
app.get("/seller/products", (req, res) => {

    if (!req.session.user || req.session.user.role !== "seller") {
        return res.status(403).json({ success:false });
    }

    const sql = `
        SELECT *
        FROM products
        WHERE seller_id = ?
        ORDER BY id DESC
    `;

    db.query(sql, [req.session.user.id], (err, rows) => {

        if (err) {
            console.error("FETCH ERROR:", err);
            return res.status(500).json({
                success: false,
                error: err.message
            });
        }

        res.json({
            success:true,
            products:rows
        });

    });
});


/* ================= UPDATE PRODUCT ================= */
app.put("/seller/product/:id", (req, res) => {

    if (!req.session.user || req.session.user.role !== "seller") {
        return res.status(403).json({ success:false });
    }

    const { name, description, category, price, stock, image } = req.body;

    const sql = `
        UPDATE products
        SET
            name=?,
            description=?,
            category=?,
            price=?,
            stock=?,
            image=?
        WHERE id=? AND seller_id=?
    `;

    db.query(sql, [
        name,
        description,
        category,
        price,
        stock,
        image,
        req.params.id,
        req.session.user.id
    ], (err, result) => {

        if (err) return res.json({ success:false });

        res.json({
            success: result.affectedRows > 0
        });

    });

});



/* ================= DELETE PRODUCT ================= */
app.delete("/seller/product/:id", (req, res) => {

    if (!req.session.user || req.session.user.role !== "seller") {
        return res.status(403).json({ success:false });
    }

    db.query(
        "DELETE FROM products WHERE id=? AND seller_id=?",
        [req.params.id, req.session.user.id],
        (err, result) => {

            if (err) return res.json({ success:false });

            res.json({
                success: result.affectedRows > 0
            });

        }
    );
});



// UPDATE ORDER STATUS (Seller / Admin)
app.put("/order/:id/status", (req, res) => {

    if (!req.session.user || !["seller", "admin"].includes(req.session.user.role)) {
        return res.status(403).json({ success: false, error: "Unauthorized" });
    }

    const { status } = req.body;
    const orderId = req.params.id;

    const allowed = ["pending", "paid", "shipped", "delivered"];
    if (!allowed.includes(status)) {
        return res.status(400).json({ success: false, error: "Invalid status" });
    }

    let sql, params;







    // 🔐 ADMIN → can update any order
    if (req.session.user.role === "admin") {
        sql = `UPDATE orders SET status=? WHERE id=?`;
        params = [status, orderId];
    }









    // 🔐 SELLER → only their product orders
    if (req.session.user.role === "seller") {
        sql = `
            UPDATE orders o
            JOIN products p ON o.product_id = p.id
            SET o.status = ?
            WHERE o.id = ? AND p.seller_id = ?
        `;
        params = [status, orderId, req.session.user.id];
    }

    db.query(sql, params, (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ success: false });
        }

        if (result.affectedRows === 0) {
            return res.status(404).json({
                success: false,
                error: "Order not found or access denied"
            });
        }

        res.json({ success: true, message: "Order status updated" });
    });
});



/* ========== SELLER VIEW ORDERS ========== */



app.get("/seller/orders", (req, res) => {

    if (!req.session.user || req.session.user.role !== "seller") {
        return res.status(403).json({ success: false });
    }

    const sellerId = req.session.user.id;

    const sql = `
        SELECT 
            o.id,
            o.quantity,
            o.status,
            o.created_at,

            p.name AS product_name,
            p.image,
            p.price,  -- ✅ ADD THIS LINE

            u.full_name AS customer_name,
            u.email AS customer_email,
            u.mobile AS customer_mobile,

            u.address1,
            u.address2,
            u.address3

        FROM orders o
        JOIN products p ON o.product_id = p.id
        JOIN users u ON o.user_id = u.id
        WHERE p.seller_id = ?
        ORDER BY o.created_at DESC
    `;

    db.query(sql, [sellerId], (err, rows) => {
        if (err) {
            console.error(err);
            return res.json({ success: false });
        }

        res.json({
            success: true,
            orders: rows
        });
    });
});




// PLACE ORDER ROUTE

app.post("/place-order", (req, res) => {

    const userId = req.session.user.id;
    const { productId, quantity } = req.body;

    const sql = `
        INSERT INTO orders 
        (user_id, product_id, quantity, status)
        VALUES (?, ?, ?, 'pending')
    `;

    db.query(sql, [userId, productId, quantity], (err) => {

        if (err) {
            return res.json({ success: false });
        }

        res.json({ success: true });

    });
});

// ✅ SELLER ANALYTICS ROUTE=====//

app.get("/seller/analytics", (req, res) => {

    if (!req.session.user || req.session.user.role !== "seller") {
        return res.status(403).json({ success: false });
    }

    const sellerId = req.session.user.id;

    const sql = `
        SELECT 
            o.id,
            o.quantity,
            o.created_at,
            p.price
        FROM orders o
        JOIN products p ON o.product_id = p.id
        WHERE p.seller_id = ?
    `;

    db.query(sql, [sellerId], (err, results) => {
        if (err) {
            console.error(err);
            return res.json({ success: false });
        }

        res.json({
            success: true,
            orders: results
        });
    });

});


/* ================= USER VIEW PRODUCTS ================= */
app.get("/products", (req, res) => {

    const sql = `
        SELECT 
            p.*, 
            u.full_name AS seller_name
        FROM products p
        JOIN users u ON p.seller_id = u.id
        ORDER BY p.created_at DESC
    `;

    db.query(sql, (err, rows) => {
        if (err) {
            console.error(err);
            return res.status(500).json({
                success: false,
                error: "Failed to load products"
            });
        }

        res.json({
            success: true,
            products: rows
        });
    });
});









// ================= SEARCH PRODUCTS =================

app.get("/search", (req, res) => {
    const search = req.query.q;

    if (!search) {
        return res.status(400).json({ message: "Search query is required" });
    }

    const sql = `
        SELECT * FROM products 
        WHERE 
            name LIKE ? 
            OR description LIKE ?
            OR category LIKE ?
            OR gender LIKE ?
        ORDER BY created_at DESC
    `;

    const value = `%${search}%`;

    db.query(sql, [value, value, value, value], (err, result) => {
        if (err) {
            console.log("Search Error:", err);
            return res.status(500).json({ message: "Server error" });
        }

        res.json(result);
    });
});













/* ================= ADD TO CART ================= */
app.post("/cart", (req, res) => {

    // 🔐 User auth
    if (!req.session.user || req.session.user.role !== "user") {
        return res.status(403).json({
            success: false,
            error: "User access only"
        });
    }

    const { product_id } = req.body;
    const userId = req.session.user.id;

    if (!product_id) {
        return res.status(400).json({
            success: false,
            error: "Product ID required"
        });
    }

    // 1️⃣ Check if product already in cart
    const checkSql = `
        SELECT id, quantity 
        FROM cart 
        WHERE user_id = ? AND product_id = ?
    `;

    db.query(checkSql, [userId, product_id], (err, rows) => {
        if (err) {
            return res.status(500).json({ success: false });
        }

        // 2️⃣ Increase quantity
        if (rows.length > 0) {
            db.query(
                "UPDATE cart SET quantity = quantity + 1 WHERE id = ?",
                [rows[0].id],
                err => {
                    if (err) return res.json({ success: false });
                    res.json({ success: true, message: "Quantity updated" });
                }
            );
        } 
        // 3️⃣ Insert new
        else {
            db.query(
                `
                INSERT INTO cart (user_id, product_id, price, quantity)
                SELECT ?, id, price, 1
                FROM products
                WHERE id = ?
                `,
                [userId, product_id],
                err => {
                    if (err) return res.json({ success: false });
                    res.json({ success: true, message: "Added to cart" });
                }
            );
        }
    });
});






/*========get user =======*/
app.get("/cart", (req, res) => {

    if (!req.session.user || req.session.user.role !== "user") {
        return res.status(403).json({ success:false });
    }

    const sql = `
        SELECT 
            c.id,
            p.name,
            p.image,
            c.price,
            c.quantity,
            (c.price * c.quantity) AS subtotal
        FROM cart c
        JOIN products p ON c.product_id = p.id
        WHERE c.user_id = ?
    `;

    db.query(sql, [req.session.user.id], (err, rows) => {
        if (err) return res.json({ success:false });

        let total = 0;

        rows.forEach(i => {
            total += Number(i.subtotal); // ✅ FORCE NUMBER
        });

        res.json({
            success: true,
            cart: rows,
            total: total.toFixed(2) // ✅ 2 decimals
        });
    });
});






/*========update cart Quantity ====*/
app.put("/cart/:id", (req, res) => {

    if (!req.session.user || req.session.user.role !== "user") {
        return res.status(403).json({ success:false });
    }

    const { action } = req.body;

    let sql = "";
    if (action === "inc") {
        sql = "UPDATE cart SET quantity = quantity + 1 WHERE id=? AND user_id=?";
    } else if (action === "dec") {
        sql = "UPDATE cart SET quantity = quantity - 1 WHERE id=? AND user_id=?";
    }

    db.query(sql, [req.params.id, req.session.user.id], err => {
        if (err) return res.json({ success:false });

        // remove if quantity <= 0
        db.query(
            "DELETE FROM cart WHERE quantity <= 0",
            ()=> res.json({ success:true })
        );
    });
});





// PLACE ORDER
app.post("/order", (req, res) => {

    if (!req.session.user || req.session.user.role !== "user") {
        return res.status(403).json({ success: false });
    }

    const userId = req.session.user.id;

    // get cart items
    db.query(
        "SELECT product_id, quantity FROM cart WHERE user_id=?",
        [userId],
        (err, cart) => {

            if (err || cart.length === 0) {
                return res.json({ success: false, error: "Cart empty" });
            }

            // prepare values
            const values = cart.map(i => [
                userId,
                i.product_id,
                i.quantity
            ]);

            // insert into orders
            db.query(
                `INSERT INTO orders (user_id, product_id, quantity)
                 VALUES ?`,
                [values],
                (err) => {

                    if (err) {
                        return res.json({ success: false });
                    }

                    // clear cart
                    db.query(
                        "DELETE FROM cart WHERE user_id=?",
                        [userId]
                    );

                    res.json({ success: true });
                }
            );
        }
    );
});




app.get("/user/orders", (req, res) => {

    if (!req.session.user || req.session.user.role !== "user") {
        return res.status(403).json({ success: false });
    }

    const userId = req.session.user.id;

    const sql = `
        SELECT 
            o.id,
            o.quantity,
            o.status,
            o.created_at,
            p.name AS product_name,
            p.image
        FROM orders o
        JOIN products p ON o.product_id = p.id
        WHERE o.user_id = ?
        ORDER BY o.created_at DESC
    `;

    db.query(sql, [userId], (err, rows) => {
        if (err) {
            console.error(err);
            return res.json({ success:false });
        }

        res.json({ success:true, orders:rows });
    });
});

// 

app.get("/orders", (req, res) => {

    if (!req.session.user || req.session.user.role !== "user") {
        return res.status(403).json({ success: false });
    }

    const sql = `
        SELECT 
            o.id,
            o.quantity,
            o.status,
            o.created_at,
            p.name,
            p.price,
            p.image
        FROM orders o
        JOIN products p ON o.product_id = p.id
        WHERE o.user_id = ?
        ORDER BY o.created_at DESC
    `;

    db.query(sql, [req.session.user.id], (err, rows) => {
        if (err) return res.json({ success: false });
        res.json({ success: true, orders: rows });
    });
});







/* ================= REMOVE FROM CART ================= */
app.delete("/cart/:id", (req, res) => {

    if (!req.session.user || req.session.user.role !== "user") {
        return res.status(403).json({ success: false });
    }

    db.query(
        "DELETE FROM cart WHERE id=? AND user_id=?",
        [req.params.id, req.session.user.id],
        err => {
            if (err) return res.json({ success: false });
            res.json({ success: true });
        }
    );
});





/*======== CLEAR CART (remove all items)========  */
app.delete("/cart", (req, res) => {
    if (!req.session.user || req.session.user.role !== "user") {
        return res.status(403).json({ success:false });
    }

    db.query(
        "DELETE FROM cart WHERE user_id=?",
        [req.session.user.id],
        err => {
            if (err) return res.json({ success:false });
            res.json({ success:true });
        }
    );
});






// /* ================= ME ================= */
// app.get("/me", (req, res) => {
//     res.setHeader("Cache-Control","no-store");
//     if (!req.session.user) {
//         return res.json({ loggedIn:false });
//     }
//     res.json({ loggedIn:true, user:req.session.user });
// });

// // /* ================= LOGOUT ================= */
// app.get("/logout", (req, res) => {
//     req.session.destroy(err => {
//         if (err) {
//             console.error("Logout error:", err);
//             return res.status(500).send("Logout failed");
//         }

//         res.clearCookie("connect.sid");
//         return res.redirect("/");
//     });
// });


function userPageSecurity(req, res, next) {

    if (!req.session || !req.session.user) {
        return res.status(401).send("Login required");
    }

    if (req.session.user.role !== "user") {
        return res.status(403).send("Access denied");
    }

    next();
}

/* ================= ME ================= */
app.get("/me", (req, res) => {
    res.setHeader("Cache-Control", "no-store");

    if (!req.session || !req.session.user) {
        return res.json({ loggedIn: false });
    }

    res.json({ loggedIn: true, user: req.session.user });
});


/* ================= LOGOUT ================= */
app.get("/logout", (req, res) => {

    if (!req.session) {
        return res.redirect("/");
    }

    req.session.destroy(err => {
        if (err) {
            console.error("Logout error:", err);
            return res.redirect("/");
        }

        res.clearCookie("connect.sid");
        return res.redirect("/");
    });
});


/* ================= START ================= */
app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
});
/* ================= LAPTOP PRODUCTS ================= */

app.get("/laptops", (req, res) => {

    const sql = `
        SELECT *
        FROM products
        WHERE category = 'laptop'
        ORDER BY created_at DESC
    `;

    db.query(sql, (err, rows) => {

        if (err) {
            console.error("Laptop Query Error:", err);
            return res.json({
                success: false
            });
        }

        res.json({
            success: true,
            products: rows
        });

    });

});
/* ================= MONITOR PRODUCTS ================= */

app.get("/monitors", (req, res) => {

    const sql = `
        SELECT *
        FROM products
        WHERE category = 'monitor'
        ORDER BY created_at DESC
    `;

    db.query(sql, (err, rows) => {

        if (err) {
            console.error("Monitor Query Error:", err);
            return res.json({
                success:false
            });
        }

        res.json({
            success:true,
            products:rows
        });

    });

});
/* ================= KEYBOARD PRODUCTS ================= */

app.get("/keyboards", (req, res) => {

    const sql = `
        SELECT *
        FROM products
        WHERE category = 'keyboard'
        ORDER BY created_at DESC
    `;

    db.query(sql, (err, rows) => {

        if (err) {
            console.error("Keyboard Query Error:", err);
            return res.json({
                success: false
            });
        }

        res.json({
            success: true,
            products: rows
        });

    });

});







/* ================= PROJECTOR PRODUCTS ================= */

app.get("/projectors", (req, res) => {

    const sql = `
        SELECT *
        FROM products
        WHERE category = 'projector'
        ORDER BY created_at DESC
    `;

    db.query(sql, (err, rows) => {

        if (err) {
            console.error("Projector Query Error:", err);
            return res.status(500).json({
                success: false,
                message: "Database error"
            });
        }

        res.json({
            success: true,
            products: rows
        });

    });

});