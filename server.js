const express = require("express");
const session = require("express-session");
const cors = require("cors");
const dotenv = require("dotenv");
const fs = require("fs");
const path = require("path");
const multer = require("multer");
const db = require("./config/db");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const bcrypt = require("bcrypt");
const nodemailer = require("nodemailer");
const crypto = require("crypto");
const cron = require('node-cron');
const cloudinary = require('cloudinary').v2;
const streamifier = require('streamifier');

dotenv.config();

const app = express();

cloudinary.config({
  cloud_name: 'dugvkviiz',
  api_key: '513258632331899',
  api_secret: 'E6x6hsKSL6LzYkYzPLCL4Ku4lY0',
});



app.use(cors({
  origin: ['http://localhost:8080', 'https://crm.wealthempires.in'],
  credentials: true
}));

app.use(express.json());


app.post("/delete_file_by_url", async (req, res) => {
  const { file_url } = req.body;
  if (!file_url || typeof file_url !== "string") {
    return res.status(400).json({ message: "Invalid file URL" });
  }

  try {
    const url = new URL(file_url);
    const parts = url.pathname.split("/");

    // Example URL: https://res.cloudinary.com/dugvkviiz/image/upload/v12345/clients/doc.pdf
    // parts: ['', 'dugvkviiz', 'image', 'upload', 'v12345', 'clients', 'doc.pdf']

    const uploadIndex = parts.findIndex(p => p === "upload");
    if (uploadIndex === -1 || parts.length <= uploadIndex + 2) {
      return res.status(400).json({ message: "Invalid Cloudinary URL structure" });
    }

    // 1. Extract the resource_type (e.g., 'image', 'video', 'raw')
    // It's the part right before '/upload/'
    const resourceType = parts[uploadIndex - 1]; 

    // 2. Extract the public_id
    // It's everything AFTER the version folder ('v12345')
    const publicIdWithExt = parts.slice(uploadIndex + 2).join("/");
    const publicId = publicIdWithExt.replace(path.extname(publicIdWithExt), "");
    
    console.log("Extracted public_id:", publicId);
    console.log("Extracted resource_type:", resourceType);

    // 3. Call destroy with the public_id and options
    const result = await cloudinary.uploader.destroy(publicId, {
      resource_type: resourceType
    });

    console.log("Cloudinary deletion result:", result);

    if (result.result === 'ok' || result.result === 'not found') {
        res.status(200).json({ message: "File deletion processed", result });
    } else {
        throw new Error(result.result);
    }

  } catch (err) {
    console.error("Cloudinary deletion error:", err);
    res.status(500).json({ message: "Failed to delete file", error: err.message });
  }
});

app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));
app.use("/uploads", express.static(path.join(__dirname, "uploads")));
app.use(
  session({
    secret: "wealthEmpire@1",
    resave: false,
    saveUninitialized: false,
    cookie: {
    maxAge:40*1000, 
    httpOnly: true,
    sameSite: "lax",
  },
  })
);
app.use(passport.initialize());
app.use(passport.session());

// Create transporter for sending emails using Outlook
const transporter = nodemailer.createTransport({
  host: "smtp.hostinger.com",
  port: 465,
  secure: true, // Use true for port 465 (SSL)
  auth: {
    user: "support@wealthempires.in", // Your full Hostinger email
    pass: "Wealthempires@1"       // App password or actual password
  },
  logger: true,   // Optional: logs to console
  debug: true     // Optional: for debugging
});

// 🔧 Enhanced Multer Storage Configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    // Generate folder name from company name or use default
    const baseName = req.body.company_name
      ? req.body.company_name
          .trim()
          .replace(/[^a-zA-Z0-9]/g, "_")
          .substring(0, 50) // Limit length to 50 chars
      : "UNKNOWN_CLIENT_" + Date.now();

    // Create folder path
    const folderPath = path.join(__dirname, "..", "uploads", "clients", baseName);
    
    // Save for later use in route
    req.uploadFolderName = baseName;
    req.uploadFolderPath = folderPath;

    // Ensure directory exists
    if (!fs.existsSync(folderPath)) {
      fs.mkdirSync(folderPath, { recursive: true });
    }

    cb(null, folderPath);
  },

  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    const field = file.fieldname.toLowerCase();
    const timestamp = Date.now();

    // Standardize filenames based on field type
    let filename;
    switch(field) {
      case 'gstin_file':
      case 'gstin':
        filename = `GSTIN_${timestamp}${ext}`;
        break;
      case 'pan_file':
      case 'pan':
        filename = `PAN_${timestamp}${ext}`;
        break;
      case 'aadhaar_file':
      case 'aadhaar':
        filename = `AADHAAR_${timestamp}${ext}`;
        break;
      case 'incorporation_file':
      case 'incorporation':
        filename = `INCORPORATION_${timestamp}${ext}`;
        break;
       case 'address':
        filename = `ADDRESS_${timestamp}${ext}`;
        break;
       case 'identity':
        filename = `IDENTITY_${timestamp}${ext}`;
        break;
               case 'photo':
        filename = `PHOTO_${timestamp}${ext}`;
        break;

      case 'bank_statement':
      case 'bank':
        filename = `BANK_STATEMENT_${timestamp}${ext}`;
        break;
      default:
        filename = `${field.toUpperCase()}_${timestamp}${ext}`;
    }

    cb(null, filename);
  }
});

// Configure Multer instance
const upload = multer({ 
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 25 * 1024 * 1024, // 25MB max per file
  },
  fileFilter: (req, file, cb) => {
    const allowedExtensions = ['.pdf', '.jpg', '.jpeg', '.png'];
    const ext = path.extname(file.originalname).toLowerCase();
    if (allowedExtensions.includes(ext)) {
      cb(null, true);
    } else {
      cb(new Error(`Invalid file type: Only ${allowedExtensions.join(', ')} are allowed`));
    }
  }
});

// Helper function to upload buffer to Cloudinary
function uploadToCloudinary(buffer, folder, publicId) {
  return new Promise((resolve, reject) => {
    const uploadStream = cloudinary.uploader.upload_stream(
      { folder, public_id: publicId },
      (error, result) => {
        if (error) return reject(error);
        resolve(result);
      }
    );
    streamifier.createReadStream(buffer).pipe(uploadStream);
  });
}

passport.use(
  new LocalStrategy(
    {
      usernameField: "email", 
      passwordField: "password",
    },
    async function (email, password, done) {
      try {
        console.log(email,password);
        const result = await db.query("SELECT * FROM users WHERE email = ?", [email]);
        console.log(result);
        if (result.length === 0) {
          return done(null, false, { message: "User not found" });
        }

        const user = result[0][0];
        const isMatch = await bcrypt.compare(password, user.password);
        if (isMatch) {
          return done(null, user);
        } else {
          return done(null, false, { message: "Incorrect password" });
          return done(null, user);
        }
      } catch (err) {
        return done(err);
      }
    }
  )
);

// Required for login sessions
passport.serializeUser((user, done) => {
  done(null, user.id);
});
passport.deserializeUser(async (id, done) => {
  const result = await db.query("SELECT * FROM users WHERE id = ?", [id]);
  done(null, result[0]);
});


// ✅ Log in route
app.post("/login", (req, res, next) => {
  passport.authenticate("local", (err, user, info) => {
    if (err) return next(err);
    if (!user) {
      return res.status(401).json({ success: false, message: info?.message || "Unauthorized" });
    }
    req.logIn(user, (err) => {
      if (err) return next(err);
      return res.json({ success: true, user });
    });
  })(req, res, next);
});
// ✅ Log out route
app.post("/logout", (req, res, next) => {
  req.logout(err => {
    if (err) return next(err);

    req.session.destroy(err => {
      if (err) {
        console.error("Failed to destroy session:", err);
        return res.status(500).json({ message: "Logout failed" });
      }

      res.clearCookie("connect.sid", {
        path: "/", // important if you set path on cookie
        httpOnly: true,
        sameSite: "lax",
      });

      res.json({ success: true, message: "Logged out successfully" });
    });
  });
});

// ✅ Register route
app.post("/register", async (req, res) => {
  const { name, email, role } = req.body;
  console.log(name,email,role);
  const password = null;
  const token = crypto.randomBytes(32).toString("hex");
  const expiry = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes validity

  if (!name || !email || !role) {
    return res.status(400).json({ success: false, message: "All fields are required." });
  }

  try {
    // Check if user already exists
    const [existing] = await db.query("SELECT * FROM users WHERE email = ?", [email]);
    if (existing.length > 0) {
      return res.status(409).json({ success: false, message: "User already exists." });
    }

    // Insert user with null password
    const [result] = await db.query(
      `INSERT INTO users (name, email, token, role, expiry, password, created_at) VALUES (?, ?, ?, ?, ?, ?, NOW())`,
      [name, email, token, role, expiry, password]
    );

    // Email content
    const mailContent = `
     <div style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; padding: 20px; max-width: 600px; margin: auto; background-color: #f9f9f9; border-radius: 8px; border: 1px solid #e0e0e0;">
  <div style="text-align: center; margin-bottom: 20px;">
    <img src="https://crm.wealthempires.in/logo.png" alt="Company Logo" style="max-height: 80px;" />
  </div>
  <p style="font-size: 20px; font-weight: bold; color: #2c3e50; margin-bottom: 10px;">Set Your Password</p>
 
  <p>Hi,</p>

  <p>We received a request to set the password for your account. To proceed, please click the button below:</p>

  <div style="text-align: center; margin: 20px 0;">
    <a href="https://crm.wealthempires.in/set-password?token=${encodeURIComponent(token)}&email=${encodeURIComponent(email)}"
      style="display: inline-block; padding: 12px 24px; background-color: #007BFF; color: white; text-decoration: none; border-radius: 6px; font-weight: bold; font-size: 16px;">
      Set Password
    </a>
  </div>

  <p>If you did not request this, you can safely ignore this email.</p>

  <p style="margin-top: 30px;">Best regards,<br><strong>Wealth Empires CRM Team</strong></p>
</div>

    `;

    // Send the email
    const mailOptions = {
      from: "support@wealthempires.in",
      to: email,
      subject: "Set your password",
      html: mailContent,
    };

    await transporter.sendMail(mailOptions);
    res.status(201).json({ success: true, message: "User registered. Password setup email sent." });

  } catch (err) {
    console.error("❌ Register error:", err);
    res.status(500).json({ success: false, message: "Server error during registration." });
  }
});


// ✅ Set password
app.post("/set-password", async (req, res) => {
  const { password,token,email } = req.body;
  // const { token, email } = req.query;

  if (!token || !email) {
    return res.status(400).json({ success: false, message: "Missing token or email." });
  }

  if (!password) {
    return res.status(400).json({ success: false, message: "Password is required." });
  }

  try {
    // Validate token and email
    const [users] = await db.query(
      "SELECT * FROM users WHERE email = ? AND token = ? AND expiry > NOW()",
      [email, token]
    );
    

    if (users.length === 0) {
      return res.status(400).json({ success: false, message: "Invalid or expired token." });
    }

    // Hash new password and update
    const hashedPassword = await bcrypt.hash(password, 12);
    await db.query(
      "UPDATE users SET password = ?, token = NULL, expiry = NULL WHERE email = ?",
      [hashedPassword, email]
    );

    return res.status(200).json({ success: true, message: "Password set successfully." });
  } catch (error) {
    console.error("Set password error:", error);
    return res.status(500).json({ success: false, message: "Server error." });
  }
});


//Reset password to default
app.post('/reset-password/:userId', async (req, res) => {
  const { userId } = req.params;

  const DEFAULT_PASSWORD = 'welcome@123';

  try {
    const hashedPassword = await bcrypt.hash(DEFAULT_PASSWORD, 12);

    const sql = 'UPDATE users SET password = ? WHERE id = ?';
    const result = await db.query(sql, [hashedPassword, userId]); 
      

      if (result.affectedRows === 0) {
        return res.status(404).json({ success: false, message: 'User not found' });
      }

      return res.json({ success: true, message: 'Password reset to default successfully' });
  } catch (error) {
    console.error('Bcrypt error:', error);
    return res.status(500).json({ success: false, message: 'Error hashing password' });
  }
});





// ✅ Get all team members
app.get("/users/team-groups", async (req, res) => {
  try {
    const [rows] = await db.query("SELECT id, name, role FROM users WHERE password IS NOT NULL;");
    const grouped = rows.reduce((acc, user) => {
      const groupName =
        user.role === "admin"
          ? "Admins"
          : user.role === "account_manager"
          ? "Account Managers"
          : user.role === "sales_staff"
          ? "Sales Staffs"
          : user.role === "filling_staff"
          ? "Filling Staffs"
          : "Others";

      if (!acc[groupName]) acc[groupName] = [];
      acc[groupName].push(user);
      return acc;
    }, {});

    const formatted = Object.entries(grouped).map(([name, members]) => ({
      name,
      members,
    }));

    res.json(formatted);
  } catch (err) {
    console.error("Error fetching users:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});



// ✅ Get all clients
app.get("/clients", async (req, res) => {
  try {
    const [results] = await db.query("SELECT * FROM clients_data");
    res.json(results);
  } catch (err) {
    console.error("Error fetching clients:", err);
    res.status(500).send("Server error while fetching clients");
  }
});

// ✅ Get specified for account managers
app.get('/clients/:userName', async (req, res) => {
  const { userName } = req.params;
  console.log(userName);

  try {
    const [rows] = await db.execute(
      'SELECT * FROM clients_data WHERE assignedTo = ? AND status NOT IN (?, ?)', 
      [userName, 'completed', 'rejected']
    );

    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server Error' });
  }
});


// ✅ Get specific client
app.get("/client/:id", async (req, res) => {
  const id = req.params.id;

  try {
    const [results] = await db.query(
      "SELECT * FROM clients_data WHERE id = ?",
      [id]
    );

    const [price] = await db.query(
      `
      SELECT 
        jt.description AS service,
        jt.unit_price AS price
      FROM billing b,
      JSON_TABLE(
        b.services,
        '$[*]' COLUMNS (
          description VARCHAR(255) PATH '$.description',
          unit_price DECIMAL(10,2) PATH '$.unit_price'
        )
      ) AS jt
      WHERE b.client_id = ?;
      `,
      [id]
    );

    if (results.length === 0) {
      return res.status(404).json({ error: "Client not found" });
    }

    const client = results[0];

    // Normalize `services` into { data, price_data }
    if (typeof client.services === "string") {
      try {
        client.services = {
          data: JSON.parse(client.services),
          price_data: price
        };
      } catch {
        client.services = {
          data: client.services.split(',').map((s) => s.trim()),
          price_data: price
        };
      }
    } else if (Array.isArray(client.services)) {
      client.services = {
        data: client.services,
        price_data: price
      };
    }

    res.json(client);
  } catch (err) {
    console.error("Error fetching client:", err);
    res.status(500).send("Server error while fetching clients");
  }
});



// ✅ Create a client
app.post(
  "/create_client",
  upload.fields([
    { name: "gstin_file", maxCount: 1 },
    { name: "pan_file", maxCount: 1 },
  ]),
  async (req, res) => {
    try {
      const {
        company_name,
        business_type,
        pan,
        gstin,
        owner_name,
        company_email,
        phone,
        address,
        services,
        status,
        revenue
      } = req.body;

      console.log(services);
      

      const servicesArray = JSON.parse(services);
      const parsedServices = JSON.stringify(servicesArray);
      const filePaths = {};
      const folder = path.join("uploads", req.uploadFolderName);
      const gstinFilePath = req.files["gstin_file"]
        ? path.join(folder, req.files["gstin_file"][0].filename)
        : null;
      const panFilePath = req.files["pan_file"]
        ? path.join(folder, req.files["pan_file"][0].filename)
        : null;

            if (req.files) {
        Object.entries(req.files).forEach(([fieldname, files]) => {
          if (files && files[0]) {
            const newFilename = `${fieldname.toUpperCase()}_${Date.now()}${path.extname(files[0].originalname)}`;
            const newPath = path.join(folder, newFilename);

            fs.mkdirSync(folder, { recursive: true });

            fs.renameSync(files[0].path, newPath);
            filePaths[fieldname] = newPath;
          }
        });
      }  

      const sql = `
      INSERT INTO clients_data 
      (company_name, business_type, pan, gstin, owner_name, company_email, phone, address, status, services, gstin_file, pan_file,revenue)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,?)
    `;
      const values = [
        company_name,
        business_type,
        pan,
        gstin,
        owner_name,
        company_email,
        phone,
        address,
        status,
        parsedServices,
        gstinFilePath,
        panFilePath,
        revenue
      ];

      const [client] = await db.query(sql, values);
      const client_id = client.insertId;

      const defaultServiceDetails = {
        status: "started",
        progress: 15,
        assignedTo: "Unassigned",
        deadline: null,
      };

      for (const type of servicesArray.map((s) => s.toLowerCase())) {
        await db.query(
          `INSERT INTO services 
         (client_id, service_type, status, progress, assignedTo, deadline, priority)
         VALUES (?, ?, ?, ?, ?, ?, get_priority_level(?))`,
          [
            client_id,
            type,
            defaultServiceDetails.status,
            defaultServiceDetails.progress,
            defaultServiceDetails.assignedTo,
            defaultServiceDetails.deadline,
            defaultServiceDetails.deadline,
          ]
        );
      }

      res
        .status(200)
        .json({ message: "✅ Client and services created successfully" });
    } catch (error) {
      console.error("❌ Error saving client:", error.message);
      if (!res.headersSent) {
        res.status(500).json({ error: "Failed to create client" });
      }
    }
  }
);

app.post("/add_client", upload.any(), async (req, res) => {
  try {
    const {
      company_name,
      business_type,
      pan,
      gstin,
      owner_name,
      company_email,
      phone,
      address,
      services,
      status,
      revenue,
      roc, // Add roc here
      shareholders // Add shareholders here
    } = req.body;
    
    console.log(req.body);
    console.log(services);
    
    const servicesArray = JSON.parse(services);
    const parsedServices = JSON.stringify(servicesArray);

    // Parse shareholders if provided
    const parsedShareholders = shareholders ? JSON.parse(shareholders) : null;

    // Create client folder
const safeCompanyName = company_name.trim().replace(/[^a-zA-Z0-9]/g, "_");
const cloudFolder = `clients/${safeCompanyName}`;

const fileUrlsByCategory = {};
const categories = Array.isArray(req.body.file_categories)
  ? req.body.file_categories
  : [req.body.file_categories]; // Handle single category

for (let i = 0; i < req.files.length; i++) {
  const file = req.files[i];
  const category = categories[i];

  if (category) {
    const safeKey = category.toLowerCase().replace(/\s+/g, "_");
    
    // Create a unique public ID for Cloudinary (optional: you can customize naming)
    const timestamp = Date.now();
    const ext = path.extname(file.originalname).toLowerCase();
    const baseName = path.basename(file.originalname, ext).replace(/[^a-zA-Z0-9]/g, "_");
    const publicId = `${safeKey}_${timestamp}_${baseName}`;

    // Upload to Cloudinary and get the file URL
    const uploadResult = await uploadToCloudinary(file.buffer, cloudFolder, publicId);

    if (!fileUrlsByCategory[safeKey]) {
      fileUrlsByCategory[safeKey] = [];
    }
    fileUrlsByCategory[safeKey].push(uploadResult.secure_url);
  }
}


    // Get least busy account manager
    const [manager] = await db.query(`
      WITH workload_cte AS (
        SELECT 
          u.id,
          u.name,
          u.last_assignment,
          COUNT(c.id) AS workload
        FROM users u
        LEFT JOIN clients_data c ON c.status NOT IN ('completed', 'rejected') AND c.assignedTo = u.id
        WHERE u.role = 'account_manager'
        GROUP BY u.id
      ),
      min_workload AS (
        SELECT MIN(workload) AS min_workload FROM workload_cte
      )
      SELECT id, name
      FROM workload_cte
      WHERE workload = (SELECT min_workload FROM min_workload)
      ORDER BY last_assignment ASC
      LIMIT 1;
    `);

    let assignedTo = null;
    let id = null;

    if (manager.length > 0) {
      assignedTo = manager[0].name;
      id = manager[0].id;
    }

    // Insert client data
  const sql = `
  INSERT INTO clients_data 
(company_name, business_type, owner_name, company_email, 
 phone, address, status, services, revenue, assignedTo, roc, shareholders)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)

`;

const values = [
  company_name,
  business_type,
  owner_name,
  company_email,
  phone,
  address,
  status,
  JSON.stringify(services), 
  revenue,
  assignedTo,
  roc,
  parsedShareholders ? JSON.stringify(parsedShareholders) : null
];



    const [client] = await db.query(sql, values);
    const client_id = client.insertId;

    // Create service records with auto-assignment
    const defaultServiceDetails = {
      status: "started",
      progress: 15,
      assignedTo: assignedTo || "Unassigned",
      deadline: null,
    };

    for (const type of servicesArray.map((s) => s.toLowerCase())) {
      await db.query(
        `INSERT INTO services 
        (client_id, service_type, status, progress, assignedAccountManager, deadline, priority)
        VALUES (?, ?, ?, ?, ?, ?, get_priority_level(?))`,
        [
          client_id,
          type,
          defaultServiceDetails.status,
          defaultServiceDetails.progress,
          defaultServiceDetails.assignedTo,
          defaultServiceDetails.deadline,
          defaultServiceDetails.deadline,
        ]
      );
    }

    // Update manager's last assignment if assigned
    if (id) {
      await db.query(
        `UPDATE users SET last_assignment = NOW() WHERE id = ?`,
        [id]
      );
    }

    res.status(200).json({ 
      message: "✅ Client and services created successfully",
      client_id,
      assigned_to: assignedTo ? manager[0].name : "Unassigned"
    });

    // Prepare billing record
    const invoiceNumber = `INV-${company_name + " " + Date.now()}`; // Unique invoice number
    const billingDate = null; // You can update this later
    const dueDate = null;
    const totalAmount = parseFloat(revenue) || 0;
    const amountPaid = 0;

    // Store basic service descriptions
    const billingServices = servicesArray.map(service => ({
      description: service,
      quantity: 1,
      unit_price: (totalAmount / servicesArray.length).toFixed(2),
    }));

    const billingSQL = `
      INSERT INTO billing (
        invoice_number, client_id, billing_date, due_date, 
        services, subtotal, tax, total_amount, amount_paid, status
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;

    const billingValues = [
      invoiceNumber,
      client_id,
      billingDate,
      dueDate,
      JSON.stringify(billingServices),
      totalAmount,       // subtotal (same as revenue here)
      0,                 // tax
      totalAmount,
      amountPaid,
      "unpaid",
    ];

    await db.query(billingSQL, billingValues);
  } catch (error) {
    console.error("❌ Error saving client:", error);
    if (!res.headersSent) {
      res.status(500).json({ 
        error: "Failed to create client",
        details: error.message 
      });
    }
  }
});

app.get("/billing_with_clients", async (req, res) => {
  try {
    const [rows] = await db.query(`
      SELECT 
        b.id AS billing_id,
        b.invoice_number,
        b.client_id,
        c.company_name,
        c.owner_name,
        c.company_email,
        c.phone,
        c.address,
        c.assignedTo,
        c.gstin,
        b.billing_date,
        b.due_date,
        b.services,
        b.subtotal,
        b.tax,
        b.total_amount,
        b.amount_paid,
        b.due_amount,
        b.status,
        b.notes,
        b.progress,
        b.payment_mode
      FROM billing b
      JOIN clients_data c ON b.client_id = c.id
      ORDER BY b.created_at DESC
    `);
    console.log(rows);

    res.status(200).json(rows);
    res.status(200).json({
      message: "✅ Client updated successfully.",
      uploaded_files: fileUrlsByCategory,
    });
  } catch (err) {
    console.error("❌ Error fetching billing info:", err);
    res.status(500).json({ error: "Server error while fetching billing info" });
    console.error("❌ Error updating client:", err);
    res.status(500).send("Server error while updating client");
  }
});

// ✅ Upload KYC files
app.post(
  "/upload_kyc/:id",
  upload.fields([
    { name: "gstin", maxCount: 1 },
    { name: "pan", maxCount: 1 },
  ]),
  async (req, res) => {
    try {
      const clientId = Number(req.params.id);
      const gstinPath = req.files["gstin"]?.[0]?.path;
      const panPath = req.files["pan"]?.[0]?.path;

      if (!gstinPath || !panPath) {
        return res.status(400).send("Both GSTIN and PAN files are required.");
      }

      const sql =
        "UPDATE clients_data SET gstin_file = ?, pan_file = ? WHERE id = ?";
      const [result] = await db.query(sql, [gstinPath, panPath, clientId]);

      if (result.affectedRows === 0) {
        return res.status(404).send("Client not found.");
      }

      res.send("✅ KYC files uploaded and paths saved.");
    } catch (err) {
      console.error("❌ DB error:", err);
      res.status(500).send("Failed to update KYC files.");
    }
  }
);

// ✅ Edit a client
app.patch("/edit_client/:id", upload.any(), async (req, res) => {
  try {
    const clientid = req.params.id;

    if (!req.body || !req.body.company_name) {
      return res.status(400).json({ message: "❌ Missing form data" });
    }

    const {
      company_name,
      business_type,
      pan,
      gstin,
      owner_name,
      company_email,
      phone,
      address,
      status,
      services,
      revenue,
      shareholders,
      service_prices,
    } = req.body;

    const servicesArray = JSON.parse(services).map((s) =>
      s.toLowerCase().trim()
    );
    const parsedShareholders = shareholders ? JSON.parse(shareholders) : null;
    const parsedServicePrices = JSON.parse(service_prices);

    const billingServices = Object.entries(parsedServicePrices).map(
      ([description, price]) => ({
        description: description.trim().toLowerCase(),
        quantity: 1,
        unit_price: price,
      })
    );

    const servicesJson = JSON.stringify(servicesArray);
    const safeCompanyName = company_name.trim().replace(/[^a-zA-Z0-9]/g, "_");
    const cloudFolder = `clients/${safeCompanyName}`;

    const fileUrlsByCategory = {};

    if (req.files?.length > 0) {
      const categories = Array.isArray(req.body.file_categories)
        ? req.body.file_categories
        : [req.body.file_categories];

      for (let i = 0; i < req.files.length; i++) {
        const file = req.files[i];
        const category = categories[i] || "uncategorized";

        const safeKey = category.toLowerCase().replace(/\s+/g, "_");
        const timestamp = Date.now();
        const ext = path.extname(file.originalname).toLowerCase();
        const baseName = path
          .basename(file.originalname, ext)
          .replace(/[^a-zA-Z0-9]/g, "_");

        const publicId = `${safeKey}_${timestamp}_${baseName}`;
        const uploadResult = await uploadToCloudinary(
          file.buffer,
          cloudFolder,
          publicId
        );

        if (!fileUrlsByCategory[safeKey]) {
          fileUrlsByCategory[safeKey] = [];
        }
        fileUrlsByCategory[safeKey].push(uploadResult.secure_url);
      }
    }

    // Fetch old services
    const [[oldClient]] = await db.query(
      "SELECT services FROM clients_data WHERE id = ?",
      [clientid]
    );

    let oldServicesArray = [];
    if (Array.isArray(oldClient.services)) {
      oldServicesArray = oldClient.services;
    } else if (typeof oldClient.services === "string") {
      try {
        oldServicesArray = JSON.parse(oldClient.services);
      } catch {
        oldServicesArray = oldClient.services.split(",").map((s) => s.trim());
      }
    }

    const isServiceChanged =
      servicesArray.length !== oldServicesArray.length ||
      !servicesArray.every((val) => oldServicesArray.includes(val));

    // Update query
    const query = `
      UPDATE clients_data
      SET
        company_name = ?,
        business_type = ?,
        pan = ?,
        gstin = ?,
        owner_name = ?,
        company_email = ?,
        phone = ?,
        address = ?,
        status = ?,
        services = ?,
        last_contact = ?,
        revenue = ?,
        shareholders = ?
      WHERE id = ?
    `;
    const values = [
      company_name,
      business_type,
      pan?.trim() || null,
      gstin?.trim() || null,
      owner_name,
      company_email,
      phone,
      address,
      status,
      servicesJson,
      new Date().toISOString().slice(0, 10),
      revenue || null,
      parsedShareholders ? JSON.stringify(parsedShareholders) : null,
      clientid,
    ];

    const [result] = await db.query(query, values);
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "❌ Client not found." });
    }

    // Update services if changed
    if (isServiceChanged) {
      for (const type of servicesArray) {
        await db.query(
          `INSERT INTO services (client_id, service_type) VALUES (?, ?)`,
          [clientid, type]
        );
      }
    }

    // Expiry date update
    const expiryDates = JSON.parse(req.body.expiry_dates || "{}");
    for (const [service, expiry] of Object.entries(expiryDates)) {
      await db.query(
        `UPDATE services SET expiry_date = ? WHERE client_id = ? AND service_type = ?`,
        [expiry, clientid, service]
      );
    }

    // Update billing
    const servicesJSON = JSON.stringify(billingServices);
    const [billing] = await db.query(
      "UPDATE billing SET total_amount = ?, services = ? WHERE client_id = ?",
      [revenue, servicesJSON, clientid]
    );

    if (billing.affectedRows === 0) {
      return res
        .status(404)
        .json({ message: "❌ Cannot update client billing" });
    }

    res.status(200).json({
      message: "✅ Client updated successfully.",
      uploaded_files: fileUrlsByCategory,
    });
  } catch (err) {
    console.error("❌ Error updating client:", err);
    res.status(500).send("Server error while updating client");
  }
});

app.get("/get_client_history/:id", async (req, res) => {
  const client_id = req.params.id;

  try {
    const [result] = await db.query(
      `SELECT 
  s.service_type,
  cd.created_at,
  cd.last_contact,
  s.assignedTo
FROM 
  services s
JOIN 
  clients_data cd ON s.client_id = cd.id
WHERE 
  s.status = 'approval'
  AND s.client_id = ?;
`,
      [client_id]
    );
    console.log(result);

    res.json(result.length > 0 ? result : []); // ✅ empty array if no match
  } catch (err) {
    console.error("❌ Cannot fetch client_history:", err);
    res.status(500).json([]); // ✅ error fallback as empty array
  }
});

app.get("/get_client_files/:company", async (req, res) => {
  const company = req.params.company.trim().replace(/ /g, '_');
  const folderPath = `clients/${company}`;  
  console.log(folderPath);

  try {
    const result = await cloudinary.api.resources({
      type: "upload",
      prefix: `${folderPath}/`, 
      max_results: 100,
    });
    console.log("result",result);

    const files = result.resources.map((file) => ({
      name: file.public_id.split("/").pop(),
      url: file.secure_url,
      type: file.format,
    }));

    res.json(files);
  } catch (err) {
    console.error("Cloudinary error:", err);
    res.status(500).json({ error: "Failed to fetch files" });
  }
});

// ✅ Get all leads
app.get("/get_client_leads", async (req, res) => {
  try {
    const [results] = await db.query("SELECT * FROM client_leads");
    res.json(results);
  } catch (err) {
    console.error("Error fetching leads:", err);
    res.status(500).send("Server error while fetching leads");
  }
});

// ✅ Edit lead (full)
app.put("/edit_lead/:id", async (req, res) => {
  const id = req.params.id;
  const body = req.body;

  if (!body.company_name || !body.owner_name || !body.services) {
    return res.status(400).json({ error: "Required fields missing." });
  }

  const sql = `
    UPDATE client_leads SET 
    company_name = ?, owner_name = ?, email = ?, phone = ?, services = ?, 
    last_contact = ?, assigned_to = ?
    WHERE id = ?
  `;

  const values = [
    body.company_name,
    body.owner_name,
    body.email || null,
    body.phone || null,
    JSON.stringify(body.services),
    body.last_contact || new Date().toISOString().slice(0, 10),
    body.assigned_to,
    id,
  ];

  try {
    const [result] = await db.query(sql, values);
    res.json({ message: "✅ Lead updated" });
  } catch (err) {
    console.error("Error updating lead:", err);
    res.status(500).send("Server error");
  }
});

app.put("/add_price/:id" , async (req,res)=>{
  const id=req.id;
  const body=req.body;
})

// ✅ Patch stage status
app.patch("/edit_lead/:id", async (req, res) => {
  const id = req.params.id;
  const { stage_status,last_update } = req.body;

  try {
    const [result] = await db.query(
      "UPDATE client_leads SET stage_status = ? and last_contact = ? WHERE id = ?",
      [stage_status,last_update, id]
    );
    res.send("✅ Stage updated successfully.");
  } catch (err) {
    console.error("Error updating stage:", err);
    res.status(500).send("Server error while updating stage.");
  }
});

// ✅ Delete lead
app.delete("/delete_lead/:id", async (req, res) => {
  try {
    const [result] = await db.query("DELETE FROM client_leads WHERE id = ?", [
      req.params.id,
    ]);
    res.json({ message: "✅ Lead deleted", result });
  } catch (err) {
    console.error("Error deleting lead:", err);
    res.status(500).send("Server error");
  }
});

// ✅ Get all Services
app.get("/get_all_services/:username", async (req, res) => {
  const { username } = req.params;
  console.log("Fetching services for:", username);

  try {
    const query = `
      SELECT 
        s.id AS service_id,
        c.company_name AS client,
        s.service_type,
        s.status,
        s.progress,
        s.assignedTo,
        s.deadline,
        s.priority
      FROM services s
      JOIN clients_data c ON s.client_id = c.id
      WHERE s.assignedAccountManager = ?
    `;

    const [results] = await db.query(query, [username]);
    console.log(results);
    res.json(results);
  } catch (err) {
    console.error("Error fetching services for user:", err);
    res.status(500).send("Server error while fetching assigned services");
  }
});


app.get("/get_all_services", async (req, res) => {
  try {
    const [results] = await db.query(`
      SELECT 
        s.id AS service_id,
        c.company_name AS client,
        s.service_type,
        s.status,
        s.progress,
        s.assignedTo,
        s.deadline,
        s.priority
      FROM services s
      JOIN clients_data c ON s.client_id = c.id
    `);

    res.json(results);
  } catch (err) {
    console.error("Error fetching all services:", err);
    res.status(500).send("Server error while fetching all services");
  }
});


// ✅ Delete lead
app.patch("/drop_lead/:id", async (req, res) => {
  try {
    const leadId = req.params.id;
    const [result] = await db.query(
      `UPDATE client_leads SET stage_status = ? WHERE id = ?`,
      ["dropped", leadId]
    );
    res.json({ message: "✅ Lead dropped", result });
  } catch (err) {
    console.error("Error dropping client lead:", err);
    res.status(500).send("Server error while fetching clients");
  }
});

// ✅ Update Service
app.patch("/update_service/:id", async (req, res) => {
  const id = req.params.id;
  console.log(id);
  const { assignedTo, deadline } = req.body;
  console.log(req.body);

  try {
    const [result] = await db.query(
      `UPDATE services 
   SET assignedTo = ?, 
       deadline = ?, 
       priority = get_priority_level(?) 
   WHERE id = ?`,
      [assignedTo, deadline, deadline, id]
    );

    res.send("✅ Updated successfully.");
  } catch (err) {
    console.error("Error updating stage:", err);
    res.status(500).send("Server error while updating stage.");
  }
});

// ✅ Update Status of service
app.patch("/update_status/:id", async (req, res) => {
  const id = req.params.id;
  console.log(req.body.id);
  console.log(id);
  const { status, progress , service_type} = req.body;
  console.log(req.body);

  try {
    const [result] = await db.query(
      "UPDATE services SET status = ?,progress = ? WHERE id = ?",
      [status, progress, id]
    );
    res.send("✅ Updated successfully.");
    if(progress===100) removeservice(id,service_type);
  } catch (err) {
    console.error("Error updating stage:", err);
    res.status(500).send("Server error while updating stage.");
  }
});

async function removeservice(id,service){

  try{
       const [result] = await db.query(
      `
 SELECT JSON_ARRAYAGG(service) AS cleaned
FROM (
  SELECT JSON_UNQUOTE(value) AS service
  FROM clients_data,
       JSON_TABLE(services, '$[*]' COLUMNS(value JSON PATH '$')) AS jt
  WHERE id = ?
    AND JSON_UNQUOTE(value) != ?
) AS filtered;
  `,
  [id, service]
    );
    const cleaned = result[0].cleaned;
    console.log(cleaned);
   const res = await db.query("UPDATE clients_data SET services = ? WHERE id = ?", [cleaned, id]);
    console.log(res);

  }
  catch(e){
    console.log("Error Occured",e);
  }

}

// Delete a service

app.delete("/delete_service", async (req, res) => {
  const { client_id, section } = req.body;
  console.log(req.body);
  console.log(client_id);
  console.log(section);

  if (!client_id || !section) {
    return res.status(400).json({ message: "Missing client_id or section" });
  }

  try {
    const [result] = await db.query(
      "DELETE FROM services WHERE id = ? AND LOWER(service_type) = ?",
      [client_id, section]
    );
    console.log("It hits!!!");

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "No matching service found" });
    console.log("It hits!!!");

    }

    res.json({ message: "✅ Service deleted successfully." });
  } catch (error) {
    console.error("❌ Error deleting service:", error);
    console.log("It hits!!!");

    res.status(500).json({ message: "Server error while deleting service." });
  }
});

// dashboard analytics stats
app.get("/dashboard_stats", async (req, res) => {
  try {
    const [rows] = await db.query(`
      SELECT 
        (SELECT COUNT(DISTINCT client_id) FROM services) AS total_clients,
        (SELECT COUNT(*) FROM clients_data WHERE status = 'active') AS active_services,
        (SELECT COUNT(*) FROM services WHERE status != 'approval' AND progress < 100) AS pending_tasks,
        (SELECT SUM(amount_paid) FROM billing WHERE status IN ('paid', 'partial')) AS total_revenue
    `);

    res.json(rows[0]);
  } catch (err) {
    console.error("❌ Error fetching dashboard stats:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Get service stats on dashboard
app.get("/get_service_stats",async(req,res)=>{
  try{
    const [rows]= await db.query(`SELECT 
  CASE 
    WHEN service_type = 'gst' THEN 'GST'
    WHEN service_type = 'itr' THEN 'ITR'
    WHEN service_type = 'mca' THEN 'MCA'
    WHEN service_type = 'ip' THEN 'IP'
    WHEN service_type = 'iso' THEN 'ISO'
    WHEN service_type = 'incorp' THEN 'INCORP'
    WHEN service_type = 'fssai' THEN 'FSSAI'
    ELSE service_type
  END AS name,

  -- Counting completed vs. total services per group
  COALESCE(SUM(CASE WHEN progress = 100 THEN 1 ELSE 0 END), 0) AS completed,
  COALESCE(COUNT(*), 0) AS total,

  -- MODIFIED: Status logic with 'complete' check first
  CASE 
    -- 1. If completed tasks equal total tasks, status is 'complete'
    WHEN COALESCE(SUM(CASE WHEN progress = 100 THEN 1 ELSE 0 END), 0) = COUNT(*) THEN 'complete'
    -- 2. Existing logic now uses MIN(deadline)
    WHEN MIN(deadline) IS NULL THEN 'no-deadline'
    WHEN DATEDIFF(MIN(deadline), CURDATE()) < 0 THEN 'behind'
    WHEN DATEDIFF(MIN(deadline), CURDATE()) > 10 THEN 'ahead'
    ELSE 'on-track'
  END AS status,

  -- MODIFIED: Fetches the earliest (minimum) deadline for the group
  MAX(deadline) AS deadline
FROM 
  services
GROUP BY 
  service_type
ORDER BY 
  -- MODIFIED: Updated sorting logic to handle the new 'complete' status
  CASE 
    WHEN DATEDIFF(MIN(deadline), CURDATE()) < 0 THEN 1 -- 'behind' first
    WHEN MIN(deadline) IS NULL THEN 4 -- 'no-deadline' after most
    WHEN COALESCE(SUM(CASE WHEN progress = 100 THEN 1 ELSE 0 END), 0) = COUNT(*) THEN 5 -- 'complete' last
    WHEN DATEDIFF(MIN(deadline), CURDATE()) > 10 THEN 3 -- 'ahead'
    ELSE 2 -- 'on-track'
  END,
  -- Secondary sort by the earliest deadline
  MIN(deadline) ASC;
`)
 res.json(rows);
  }
  catch(e){
    console.log("Error fetching service stats",e);
  }
});

// get upcoming dues shown in dashboard
app.get("/get_upcoming_deadlines",async (req,res)=>{
  console.log(process.env.DB_HOST);
  try{
    const [rows] = await db.query(`SELECT 
  s.id,
  CASE 
    WHEN s.service_type = 'incorp' THEN 'INCORPORATION'
    WHEN s.service_type = 'gst' THEN 'GST Filing'
    WHEN s.service_type = 'itr' THEN 'ITR Filing'
    WHEN s.service_type = 'mca' THEN 'MCA Annual Return'
    WHEN s.service_type = 'ip' THEN ' IP Trademark Renewal'
    WHEN s.service_type = 'iso' THEN 'ISO'
    WHEN s.service_type = 'fssai' THEN 'FSSAI'

    ELSE 'Other Service'
  END AS title,

  c.company_name AS client,
  s.deadline AS date,
  DATEDIFF(s.deadline, CURDATE()) AS daysLeft,

  CASE 
    WHEN DATEDIFF(s.deadline, CURDATE()) < 5 THEN 'high'
    WHEN DATEDIFF(s.deadline, CURDATE()) < 15 THEN 'medium'
    ELSE 'low'
  END AS priority

FROM services s
JOIN clients_data c ON s.client_id = c.id
WHERE s.deadline IS NOT NULL
  AND DATEDIFF(s.deadline, CURDATE()) <= 40
  AND DATEDIFF(s.deadline, CURDATE()) >= 0
  AND s.status != "approval"
ORDER BY daysLeft ASC;
`)
res.json(rows);
  }
  catch(e){
    console.log("Error Fetching Deadlines",err);
  }
});

// Get Dues of Clients shown in dashboard
app.get("/get_dues",async (req,res)=>{
  try{
    const [rows]=await db.query(`SELECT 
  s.id,
  
  -- Map internal service_type codes to readable service titles
  CASE 
    WHEN s.service_type = 'incorp' THEN 'INCORPORATION'
    WHEN s.service_type = 'gst' THEN 'GST Filing'
    WHEN s.service_type = 'itr' THEN 'ITR Filing'
    WHEN s.service_type = 'mca' THEN 'MCA Annual Return'
    WHEN s.service_type = 'ip' THEN 'Trademark Renewal'
    ELSE 'Other Service'
  END AS title,

  -- Client company name
  c.company_name AS client,

  -- Deadline of the service
  s.deadline AS date,

  -- Days since the deadline (negative indicates it's overdue)
  DATEDIFF(s.deadline, CURDATE()) AS daysOverdue,

  -- Hardcoded status as overdue
  'overdue' AS status

FROM services s

-- Join with client details
JOIN clients_data c ON s.client_id = c.id

-- Filter only overdue and incomplete services
WHERE s.deadline IS NOT NULL
  AND DATEDIFF(s.deadline, CURDATE()) < 0
  AND s.progress != 100

-- Order by most overdue first
ORDER BY daysOverdue ASC;
`);
res.json(rows);
  }
  catch(err){
    console.log("Maybe no dues left" , err);
    // res.json([]);
  }
});

// Client files query
app.get('/client-files/:companyName', (req, res) => {
  const companyName = req.params.companyName;
  const folderPath = path.join('uploads', companyName);
  
  try {
    if (!fs.existsSync(folderPath)) {
      return res.json([]);
    }
    
    const files = fs.readdirSync(folderPath).map(file => {
      return {
        name: file,
        path: path.join(folderPath, file),
        url: `${path.join(folderPath, file)}` 
      };
    });
    
    res.json(files);
  } catch (err) {
    console.error('Error reading files:', err);
    res.status(500).json({ error: 'Failed to read files' });
  }
});

//Update Payment method 
app.patch("/update_payment/:id", async (req, res) => {
  const client_id = req.params.id;
  const { total_payment, payment, deadline,payment_method } = req.body;

  try {
    const total = parseFloat(total_payment);
    const paid = parseFloat(payment);

    const [result] = await db.query(
      `UPDATE billing 
       SET total_amount = ?, 
           amount_paid = ?, 
           due_date = ?, 
           payment_mode = ?,
           status = get_billing_status(?, ?, ?) 
       WHERE client_id = ?`,
      [total, paid, deadline,payment_method, paid, total, deadline, client_id]
    );

    res.json({ message: "Billing updated successfully", updated: result.affectedRows });
  } catch (err) {
    console.error("Error updating billing:", err);
    res.status(500).json({ error: "Failed to update billing" });
  }
});
// Get analytics of analytics page of Services
app.get("/get_analytics",async (req,res)=>{
  const query=`SELECT service_type, COUNT(*) AS count FROM services GROUP BY service_type;`
  
  try{
    const [rows]=await db.query(query);
    res.send(rows);
  }
  catch(e){
    console.log(e,"error");
  }
});
// Revenue Analytics
  app.get("/get_revenue_analytics",async (req,res)=>{
  const query=`WITH months AS (
  SELECT
    DATE_FORMAT(DATE_SUB(CURDATE(), INTERVAL n MONTH), '%b') AS month,
    MONTH(DATE_SUB(CURDATE(), INTERVAL n MONTH)) AS month_number
  FROM (
    SELECT 0 AS n UNION SELECT 1 UNION SELECT 2 UNION SELECT 3 UNION SELECT 4 UNION SELECT 5
  ) AS numbers
),
billing_data AS (
  SELECT
    DATE_FORMAT(GREATEST(IFNULL(updated_at, created_at), created_at), '%b') AS month,
    MONTH(GREATEST(IFNULL(updated_at, created_at), created_at)) AS month_number,
    SUM(amount_paid) AS revenue,
    COUNT(DISTINCT client_id) AS clients
  FROM billing
  WHERE GREATEST(IFNULL(updated_at, created_at), created_at) >= DATE_SUB(CURDATE(), INTERVAL 6 MONTH)
  GROUP BY month_number, month
)
SELECT
  m.month,
  m.month_number,
  IFNULL(b.revenue, 0) AS revenue,
  IFNULL(b.clients, 0) AS clients
FROM months m
LEFT JOIN billing_data b ON m.month_number = b.month_number
ORDER BY m.month_number;
`
  
  try{
    const [rows]=await db.query(query);
    res.send(rows);
  }
  catch(e){
    console.log(e,"error");
  }
});

//Analytics page dashboard data query
app.get("/get_dashboard_analytics", async (req, res) => {
  const mainQuery = `
    SELECT
      (SELECT SUM(amount_paid) FROM billing WHERE status IN ('paid', 'partial')) AS total_revenue,
      (SELECT COUNT(DISTINCT cd.id)
       FROM clients_data cd
       JOIN services s ON cd.id = s.client_id
       WHERE cd.status = 'active') AS active_clients,
      (SELECT COUNT(*) FROM services WHERE LOWER(status) = 'completed' OR progress = 100) AS services_completed,
      (SELECT 
         ROUND(
           (SUM(CASE WHEN LOWER(status) = 'completed' OR progress = 100 THEN 1 ELSE 0 END) * 100.0)
           / COUNT(*),
           2
         )
       FROM services) AS efficiency_rate;
  `;

  const taxQuery = `
SELECT
  DATE_FORMAT(deadline, '%b') AS month,
  MONTH(deadline) AS month_num,
  SUM(CASE WHEN LOWER(service_type) LIKE '%gst%' THEN 1 ELSE 0 END) AS gst_count,
  SUM(CASE WHEN LOWER(service_type) LIKE '%itr%' THEN 1 ELSE 0 END) AS itr_count
FROM services
WHERE deadline IS NOT NULL
  AND (LOWER(service_type) LIKE '%gst%' OR LOWER(service_type) LIKE '%itr%')
GROUP BY month_num, month
ORDER BY month_num;
  `;

  const leadQuery = `
SELECT
  SUM(CASE WHEN LOWER(stage_status) = 'new' THEN 1 ELSE 0 END) AS new_leads,
  SUM(CASE WHEN LOWER(stage_status) = 'contacted' THEN 1 ELSE 0 END) AS contacted_leads,
  SUM(CASE WHEN LOWER(stage_status) = 'converted' THEN 1 ELSE 0 END) AS converted_leads,
  SUM(CASE WHEN LOWER(stage_status) = 'dropped' THEN 1 ELSE 0 END) AS dropped_leads
FROM client_leads
WHERE last_contact >= DATE_SUB(CURDATE(), INTERVAL 6 MONTH);`
;

  try { 
    const [mainResult] = await db.query(mainQuery);
    const [taxResult] = await db.query(taxQuery);
    const [leadResult] = await db.query(leadQuery);

const taxData = taxResult.map((row) => ({
  month: row.month,
  gst: parseInt(row.gst_count ?? 0),
  itr: parseInt(row.itr_count ?? 0),
}));

const leadData = {
  new_leads: parseInt(leadResult[0]?.new_leads ?? 0),
  contacted_leads: parseInt(leadResult[0]?.contacted_leads ?? 0),
  converted_leads: parseInt(leadResult[0]?.converted_leads ?? 0),
  dropped_leads: parseInt(leadResult[0]?.dropped_leads ?? 0),
};



    res.json({
      ...mainResult[0],
      taxData,
      leadData,
    });
  } catch (e) {
    console.error("Dashboard analytics error:", e);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Team performance graph
app.get("/team_performance",async(req,res)=>{
  const query=`SELECT 
  UPPER(service_type) AS team,
  COUNT(*) AS total_services,
  SUM(CASE WHEN progress = 100 OR LOWER(status) = 'completed' THEN 1 ELSE 0 END) AS completed_services,
  ROUND(
    SUM(CASE WHEN progress = 100 OR LOWER(status) = 'completed' THEN 1 ELSE 0 END) * 100 / COUNT(*),
    2
  ) AS efficiency
FROM services
WHERE service_type IN ('incorp', 'gst', 'itr', 'mca', 'ip', 'iso', 'fssai')
GROUP BY service_type;
`;
   try{
    const [rows]=await db.query(query);
    res.send(rows);
   }
   catch(e){
    console.log(e,"error");
   }

});

//Get user
app.get("/get_user/:userName", async (req, res) => {
  console.log("It hits!!");
  const userName = req.params.userName;
  if (!userName) return res.status(400).json({ message: "Username required" });
  const query=`SELECT * FROM users WHERE name = "${userName}"`;

  try{
  const [rows]=await db.query(query);
  res.send(rows);
   }
   catch(e){
    console.log(e,"error");
   }

});

app.post("/update_profile", async (req, res) => {
  const { name, email, password, newPassword } = req.body;

  if (!password) {
    return res.status(400).json({ message: "Current password is required." });
  }

  try {
    // Get user by either email or name
    const [rows] = await db.query(
      "SELECT id, password FROM users WHERE email = ? OR name = ?",
      [email, name]
    );

    if (rows.length === 0) {
      return res.status(404).json({ message: "User not found." });
    }

    const user = rows[0];

    // Validate current password
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) {
      return res.status(401).json({ message: "Invalid password." });
    }
    let query = "UPDATE users SET name = ?, email = ?";
    const values = [name, email];

    if (newPassword) {
      const hashed = await bcrypt.hash(newPassword, 10);
      query += ", password = ?";
      values.push(hashed);
    }

    query += " WHERE id = ?";
    values.push(user.id);

    // Execute update
    await db.query(query, values);
    res.json({ message: "Profile updated successfully." });

  } catch (err) {
    console.error("Error updating profile:", err);
    res.status(500).json({ message: "Server error." });
  }
});


//email remainder for clients
async function sendReminderEmail(to, subject, htmlContent) {
  console.log(to,subject,htmlContent);
  try {
      const mailOptions = {
      from: "support@wealthempires.in",
      to: to,
      subject: subject,
      html: htmlContent,
    };
    await transporter.sendMail(mailOptions);
    console.log(`✅ Email sent to ${to}`);
  } catch (error) {
    console.error(`❌ Failed to send email to ${to}:`, error);
  }
}




function formatDate(date) {
  return date.toISOString().split('T')[0];
}

async function sendReminderEmail(to, subject, html) {
  try {
    const mailOptions = {
      from: 'support@wealthempires.in',
      to,
      subject,
      html
    };
    // Test the email transporter
transporter.verify(function(error, success) {
  if (error) {
    console.log('SMTP Connection Error:', error);
  } else {
    console.log('SMTP Server is ready to take our messages');
  }
});
    const info = await transporter.sendMail(mailOptions);
    console.log('Message sent: %s', info.messageId);
    return true;
  } catch (error) {
    console.error('Error sending email:', error);
    return false;
  }
}

function formatDate(date) {
  return date.toISOString().split('T')[0];
}

// Reminder 
async function checkAndSendReminders() {
  try {
    const today = new Date();
    const formattedToday = formatDate(today);
    const plus2 = formatDate(new Date(Date.now() + 2 * 24 * 60 * 60 * 1000));
    const plus7 = formatDate(new Date(Date.now() + 7 * 24 * 60 * 60 * 1000));

    // ========================
    // 1. BILLING REMINDERS
    // ========================
    const billingQuery = `
      SELECT 
        b.id AS billing_id,
        b.invoice_number,
        b.client_id,
        b.due_date,
        b.total_amount,
        b.due_amount,
        c.company_name,
        c.company_email
      FROM billing b
      JOIN clients_data c ON b.client_id = c.id
      WHERE b.status IN ('unpaid', 'partial') AND (
        DATEDIFF(b.due_date, ?) = 7 OR
        DATEDIFF(b.due_date, ?) = 1
      );
    `;
    
    try {
      const [billingRows] = await db.query(billingQuery, [formattedToday, formattedToday]);
      console.log('Billing rows:', billingRows);
      
      for (const row of billingRows) {
        const subject = `Reminder: Invoice #${row.invoice_number} due on ${row.due_date}`;
        const html = `
<div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #eee; background-color: #fafafa;">
  <h2 style="color: #333; text-align: center; border-bottom: 1px solid #ddd; padding-bottom: 10px;">Payment Reminder</h2>

  <p style="font-size: 16px;">Dear <strong>${row.company_name}</strong>,</p>
  <p style="font-size: 15px;">This is a kind reminder that your payment is due soon. Kindly review the invoice details below:</p>

  <table style="width: 100%; margin: 20px 0; border-collapse: collapse; font-size: 15px;">
    <tr>
      <td style="padding: 8px 0;"><strong>Invoice Number:</strong></td>
      <td>${row.invoice_number}</td>
    </tr>
    <tr>
      <td style="padding: 8px 0;"><strong>Due Date:</strong></td>
      <td>${new Date(row.due_date).toLocaleDateString()}</td>
    </tr>
    <tr>
      <td style="padding: 8px 0;"><strong>Total Amount:</strong></td>
      <td>₹${row.total_amount}</td>
    </tr>
    <tr>
      <td style="padding: 8px 0;"><strong>Pending Amount:</strong></td>
      <td>₹${row.due_amount}</td>
    </tr>
  </table>

  <p style="font-size: 15px;">Please ensure the payment is completed before the due date to avoid any late fees.</p>

  <!-- Footer with logo -->
  <div style="margin-top: 40px; border-top: 1px solid #ddd; padding-top: 20px; text-align: center;">
    <img src="https://crm.wealthempires.in/logo.png" alt="Wealth Empires Logo" style="height: 40px; margin-bottom: 10px;" />
    <p style="font-size: 14px; color: #777;">Wealth Empires Pvt. Ltd.</p>
    <p style="font-size: 13px; color: #aaa;">This is an automated reminder email. Please do not reply to this message.</p>
  </div>
</div>

        `;
        
        console.log('Sending to:', row.company_email);
        await sendReminderEmail(row.company_email, subject, html);
      }
    } catch(e) {
      console.log('Billing query error:', e);
    }

    // ========================
    // 2. SERVICE EXPIRY REMINDERS
    // ========================
    const serviceQuery = `
      SELECT 
        s.client_id,
        s.service_type,
        s.expiry_date,
        c.company_name,
        c.company_email
      FROM services s
      JOIN clients_data c ON s.client_id = c.id
      WHERE s.expiry_date IN (?, ?, ?);
    `;
    
    try {
      const [serviceRows] = await db.query(serviceQuery, [formattedToday, plus2, plus7]);
      console.log('Service rows:', serviceRows);
      
      for (const row of serviceRows) {
        const expiry = new Date(row.expiry_date);
        const daysLeft = Math.ceil((expiry.getTime() - today.getTime()) / (1000 * 60 * 60 * 24));

        let subject = '';
        let message = '';

        if (daysLeft === 7) {
          subject = `⏳ 7 Days Left: ${row.service_type.toUpperCase()} Expiry Reminder`;
          message = `This is a reminder that your ${row.service_type.toUpperCase()} service is expiring in 7 days on ${new Date(row.expiry_date).toLocaleDateString()}.`;
        } else if (daysLeft === 2) {
          subject = `⚠️ 2 Days Left: ${row.service_type.toUpperCase()} Expiry Reminder`;
          message = `Only 2 days left! Your ${row.service_type.toUpperCase()} service expires on ${new Date(row.expiry_date).toLocaleDateString()}.`;
        } else if (daysLeft === 0) {
          subject = `❗ Expiring Today: ${row.service_type.toUpperCase()} Service`;
          message = `Your ${row.service_type.toUpperCase()} service is expiring today (${new Date(row.expiry_date).toLocaleDateString()}).`;
        } else {
          continue;
        }

        const html = `
<div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #eee; background-color: #f9f9f9;">
  <h2 style="color: #333; text-align: center; border-bottom: 1px solid #ddd; padding-bottom: 10px;">
    Service Expiry Reminder
  </h2>

  <p style="font-size: 16px;">Dear <strong>${row.company_name}</strong>,</p>
  <p style="font-size: 15px;">${message}</p>
  <p style="font-size: 15px;">Please take the necessary steps to renew or follow up on this service before it expires.</p>

  <!-- Footer -->
  <div style="margin-top: 40px; border-top: 1px solid #ddd; padding-top: 20px; text-align: center;">
    <img src="https://crm.wealthempires.in/logo.png" alt="Wealth Empires Logo" style="height: 40px; margin-bottom: 10px;" />
    <p style="font-size: 14px; color: #555;">Wealth Empires Pvt. Ltd.</p>
    <p style="font-size: 13px; color: #999;">This is an automated notification. No reply is necessary.</p>
  </div>
</div>

        `;
        
        console.log('Sending to:', row.company_email);
        await sendReminderEmail(row.company_email, subject, html);
      }
    } catch(e) {
      console.log('Service query error:', e);
    }

    console.log(`✅ Reminder job completed at ${new Date().toISOString()}`);
  } catch (error) {
    console.error("❌ Error in combined reminder job:", error);
  }
}


// Schedule the job to run daily at 9,1,6.
cron.schedule('0 9,13,18 * * *', () => {
  console.log('⏰ Running scheduled reminder job at 9 AM / 1 PM / 6 PM...');
  checkAndSendReminders();
});

// Delete a user
app.delete("/delete_user/:id", async (req, res) => {
  const userId = req.params.id;

  try {
    const [result] = await db.execute("DELETE FROM users WHERE id = ?", [userId]);

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json({ message: "✅ User deleted successfully" });
  } catch (error) {
    console.error("❌ Error deleting user:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Edit user of admin side whether they can be either admin,account manager,Filling staff,Sales Staff
app.patch("/edit_user/:id", async (req, res) => {
  const { id } = req.params;
  const { name } = req.body;

  try {
    await db.query(
      "UPDATE users SET name = ? WHERE id = ?",
      [name, id]
    );

    res.json({ success: true, message: "Client updated successfully." });
  } catch (error) {
    console.error("❌ Error updating client:", error);
    res.status(500).json({ success: false, error: "Failed to update client." });
  }
});



// Optional: Manual trigger route
app.get('/trigger-reminders', async (req, res) => {
  await checkAndSendReminders();
  res.send('Reminder job triggered manually.');
});

// Report metrics of start and end date as parameters
app.get("/report_metrics", async (req, res, next) => {
  const { startDate, endDate } = req.query;

  if (!startDate || !endDate) {
    return res.status(400).json({ error: "startDate and endDate are required" });
  }

  try {
    const [
      [leadMetrics],
      [billingMetrics],
      [serviceMetrics],
      [customerMetrics],
    ] = await Promise.all([
      db.query(
        `SELECT
  COUNT(*) AS total_leads,
  SUM(JSON_LENGTH(services)) AS total_requested_services,
  SUM(stage_status = 'dropped') AS dropped_leads,
  SUM(stage_status = 'completed') AS converted_leads
FROM client_leads
WHERE last_contact BETWEEN ? AND ?;
`,
        [startDate, endDate]
      ),
      db.query(
        `SELECT
            COUNT(*) AS total_invoices,
            SUM(total_amount) AS total_billed,
            SUM(amount_paid) AS total_received,
            SUM(due_amount) AS total_due
         FROM billing
         WHERE created_at BETWEEN ? AND ?`,
        [startDate, endDate]
      ),
      db.query(
        `SELECT
            COUNT(*) AS total_services,
            SUM(CASE WHEN progress >= 100 THEN 1 ELSE 0 END) AS completed_services,
            AVG(progress) AS avg_progress
         FROM services
         WHERE deadline BETWEEN ? AND ?`,
        [startDate, endDate]
      ),
      db.query(
        `SELECT
            COUNT(DISTINCT client_id) AS total_customers
         FROM billing
         WHERE created_at BETWEEN ? AND ?`,
        [startDate, endDate]
      ),
    ]);

    res.json({
      leadMetrics: leadMetrics[0],
      billingMetrics: billingMetrics[0],
      serviceMetrics: serviceMetrics[0],
      customerMetrics: customerMetrics[0],
    });
  } catch (err) {
    next(err);
  }
});

//delete cloudinary file




const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
