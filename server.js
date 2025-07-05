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

dotenv.config();

const app = express();
app.use(cors({
  origin: "http://localhost:8080", // ✅ allow your frontend origin only
  credentials: true, // ✅ allow cookies
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use("/uploads", express.static(path.join(__dirname, "uploads")));
app.use(
  session({
    secret: "secretkey123",
    resave: false,
    saveUninitialized: false,
    cookie: {
    maxAge:40*1000, // 1 day
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
  storage,
  limits: {
    fileSize: 25 * 1024 * 1024, // 25MB per file
    files: 10 // Maximum 10 files
  },
  fileFilter: (req, file, cb) => {
    // Validate file extensions
    const allowedExtensions = ['.pdf', '.jpg', '.jpeg', '.png'];
    const ext = path.extname(file.originalname).toLowerCase();
    
    if (allowedExtensions.includes(ext)) {
      cb(null, true);
    } else {
      cb(new Error(`Invalid file type: Only ${allowedExtensions.join(', ')} are allowed`));
    }
  }
});

passport.use(
  new LocalStrategy(
    {
      usernameField: "email", // matches `req.body.email` from frontend
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
      <div style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; padding: 20px;">
        <p style="font-size: 18px; font-weight: bold; color: #2c3e50;">Set Password</p>
        <p>We received a request to set the password for your account. Please click the link below:</p>
        <a href="http://localhost:8080/set-password?token=${encodeURIComponent(token)}&email=${encodeURIComponent(email)}"
          style="display: inline-block; padding: 10px 20px; background-color: #007BFF;
          color: white; text-decoration: none; border-radius: 5px; font-weight: bold; margin-top: 10px;">
          Set Password
        </a>
        <p style="margin-top: 20px;">Once your password is set, you can log in.</p>
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
    const [results] = await db.query("SELECT * FROM clients_data WHERE id=?", [
      id,
    ]);

    if (results.length === 0) {
      return res.status(404).json({ error: "Client not found" });
    }

    const client = results[0];

    // Convert services to array if stored as string
    if (typeof client.services === "string") {
      try {
        client.services = JSON.parse(client.services);
      } catch {
        client.services = [];
      }
    }

    res.json(client); // ✅ now returning an object, not array
  } catch (err) {
    console.error("Error fetching clients:", err);
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
            const newPath = path.join(uploadFolder, newFilename);
            
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

app.post(
  "/add_client",
  upload.any(),
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
      console.log(req.body);
      console.log(services);

      const servicesArray = JSON.parse(services);
      const parsedServices = JSON.stringify(servicesArray);

// Create client folder
const folder = path.join("uploads", company_name);
if (!fs.existsSync(folder)) {
  fs.mkdirSync(folder, { recursive: true });
}

const filePaths = {};
const categories = Array.isArray(req.body.file_categories)
  ? req.body.file_categories
  : [req.body.file_categories]; // in case only one category sent

// Process each uploaded file
for (let i = 0; i < req.files.length; i++) {
  const file = req.files[i];
  const category = categories[i];
  
  if (category) {
    const safeKey = category.toLowerCase().replace(/\s+/g, "_");
    const fileExt = path.extname(file.originalname);
    const fileName = `${safeKey}${fileExt}`;
    const filePath = path.join(folder, fileName);
    
    // Move the file from temp location to our folder
    fs.renameSync(file.path, filePath);
    
    // Store the new path
    filePaths[safeKey] = filePath;
  }
}    // Get least busy account manager
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
        (company_name, business_type, pan, gstin, owner_name, company_email, 
         phone, address, status, services, gstin_file, pan_file, aadhar_file, 
         incorporation_file, bank_statement, revenue,assignedTo)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,?)
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
        filePaths.gstin_file || null,
        filePaths.pan_file || null,
        filePaths.aadhaar_file || null,
        filePaths.incorporation_file || null,
        filePaths.bank_statement || null,
        revenue,
        assignedTo
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
const invoiceNumber = `INV-${company_name + " "+ Date.now()}`; // Unique invoice number
const billingDate = null; // You can update this later
const dueDate = null;
const totalAmount = parseFloat(revenue) || 0;
const amountPaid = 0;

// Store basic service descriptions
const billingServices = servicesArray.map(service => ({
  description: service,
  quantity: 1,
  unit_price: (totalAmount / servicesArray.length).toFixed(2)
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
  "unpaid"
];

await db.query(billingSQL, billingValues);
 
    
}
    
    catch (error) {
      console.error("❌ Error saving client:", error);
      if (!res.headersSent) {
        res.status(500).json({ 
          error: "Failed to create client",
          details: error.message 
        });
      }
    }
  }
);

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
app.patch(
  "/edit_client/:id",
  upload.any(),
  async (req, res) => {
    console.log("🔥 req.body:", req.body);
    console.log("📁 req.files:", req.files);

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
        revenue
      } = req.body;

      const servicesArray = JSON.parse(services).map((s) =>
        s.toLowerCase().trim()
      );

      const servicesJson = JSON.stringify(servicesArray);

      // Create client folder if it doesn't exist
     // Create client folder
const folder = path.join("uploads", company_name);
if (!fs.existsSync(folder)) {
  fs.mkdirSync(folder, { recursive: true });
}

// Initialize object to hold file paths
const filePaths = {};

// Get file categories from request body
const categories = Array.isArray(req.body.file_categories)
  ? req.body.file_categories
  : [req.body.file_categories]; // if only one category was sent

// Loop through each uploaded file
const existingFiles = fs.readdirSync(folder) || [];
let fileCounter = existingFiles.length + 1;

for (const file of req.files) {
  const fileExt = path.extname(file.originalname);
  const fileName = `file_${fileCounter}${fileExt}`;
  const filePath = path.join(folder, fileName);

  fs.renameSync(file.path, filePath);

  // Store relative path
  filePaths[`file_${fileCounter}`] = path
    .join("uploads", company_name.replace(/[^a-z0-9]/gi, "_"), fileName)
    .replace(/\\/g, '/');

  fileCounter++;
}

      // Get old services from DB
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
        } catch (err) {
          oldServicesArray = oldClient.services.split(",").map(s => s.trim());
        }
      }
      oldServicesArray = oldServicesArray.map((s) => s.toLowerCase());

      const isServiceChanged =
        servicesArray.length !== oldServicesArray.length ||
        !servicesArray.every((val) => oldServicesArray.includes(val));

      // Build SQL query dynamically based on available fields
      let query = `
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
          revenue = ?
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
        servicesJson,
        new Date().toISOString().slice(0, 10),
        revenue,
      ];

      // Add file paths to query if files were uploaded
      // Object.entries(filePaths).forEach(([fieldName, filePath]) => {
      //   query += `, ${fieldName} = ?`;
      //   values.push(filePath);
      // });

      query += " WHERE id = ?";
      values.push(clientid);

      const [result] = await db.query(query, values);

      // Only insert new services if changed
      if (isServiceChanged) {
        for (const type of servicesArray) {
          await db.query(
            `INSERT INTO services (client_id, service_type)
             VALUES (?, ?)`,
            [clientid, type]
          );
        }
      }

      if (result.affectedRows === 0) {
        return res.status(404).json({ message: "❌ Client not found." });
      }

      const [billing]=await db.query("UPDATE billing SET total_amount = ? WHERE client_id = ?",[revenue,clientid]);
        if (billing.affectedRows === 0) {
        return res.status(404).json({ message: "❌ Cannot update client billing" });
      }

      res.status(200).json({ 
        message: "✅ Client updated successfully.",
        files: filePaths
      });
    } catch (err) {
      console.error("❌ Error updating client:", err);
      res.status(500).send("Server error while updating client");
    }
  }
);

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
        b.progress
      FROM billing b
      JOIN clients_data c ON b.client_id = c.id
      ORDER BY b.created_at DESC
    `);
    console.log(rows);

    res.status(200).json(rows);
  } catch (err) {
    console.error("❌ Error fetching billing info:", err);
    res.status(500).json({ error: "Server error while fetching billing info" });
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

// ✅ Delete a client
app.delete("/delete_client/:id", async (req, res) => {
  const clientId = req.params.id;

  try {
    // Delete services (if any) — no problem if none exist
    await db.query("DELETE FROM services WHERE client_id = ?", [clientId]);

    // Then delete the client
    const [clientResult] = await db.query(
      "DELETE FROM clients_data WHERE id = ?",
      [clientId]
    );

    if (clientResult.affectedRows === 0) {
      return res.status(404).send("❌ Client not found.");
    }

    res.send("✅ Client deleted successfully.");
  } catch (err) {
    console.error("❌ Error deleting client:", err);
    res.status(500).send("Failed to delete client.");
  }
});

// ✅ Add a lead
app.post("/add-lead", async (req, res) => {
  const body = req.body;
  if (!body.company_name || !body.owner_name || !body.services) {
    return res.status(400).json({ error: "Required fields missing." });
  }

  try {
    const sql = `
      INSERT INTO client_leads 
      (company_name, owner_name, email, phone, services, last_contact, assigned_to, stage_status)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `;
    const values = [
      body.company_name,
      body.owner_name,
      body.email || null,
      body.phone || null,
      JSON.stringify(body.services),
      body.last_contact || new Date().toISOString().slice(0, 10),
      body.assigned_to,
      body.stage_status,
    ];
    const [result] = await db.query(sql, values);
    res.status(201).json({ message: "Lead saved", id: result.insertId });
  } catch (err) {
    console.error("Insert error:", err);
    res.status(500).json({ error: "Database error" });
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

// ✅ Patch stage status
app.patch("/edit_lead/:id", async (req, res) => {
  const id = req.params.id;
  const { stage_status } = req.body;

  try {
    const [result] = await db.query(
      "UPDATE client_leads SET stage_status = ? WHERE id = ?",
      [stage_status, id]
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
      WHERE s.assignedTo = ?
    `;

    const [results] = await db.query(query, [username]);
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

// ✅ Update Service
app.patch("/update_status/:id", async (req, res) => {
  const id = req.params.id;
  console.log(id);
  const { status, progress } = req.body;
  console.log(req.body);

  try {
    const [result] = await db.query(
      "UPDATE services SET status = ?,progress = ? WHERE id = ?",
      [status, progress, id]
    );
    res.send("✅ Updated successfully.");
  } catch (err) {
    console.error("Error updating stage:", err);
    res.status(500).send("Server error while updating stage.");
  }
});

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


app.get("/dashboard_stats", async (req, res) => {
  try {
    const [rows] = await db.query(`
      SELECT 
        (SELECT COUNT(DISTINCT client_id) FROM services) AS total_clients,
        (SELECT COUNT(*) FROM clients_data WHERE status = 'active') AS active_services,
        (SELECT COUNT(*) FROM services WHERE status != 'approval' AND progress < 100) AS pending_tasks,
        (SELECT SUM(revenue) FROM clients_data) AS total_revenue
    `);

    res.json(rows[0]);
  } catch (err) {
    console.error("❌ Error fetching dashboard stats:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});


app.get("/get_service_stats",async(req,res)=>{
  try{
    const [rows]= await db.query(`SELECT 
  CASE 
    WHEN service_type = 'gst' THEN 'GST Filing'
    WHEN service_type = 'itr' THEN 'ITR Processing'
    WHEN service_type = 'mca' THEN 'MCA Compliance'
    WHEN service_type = 'ip' THEN 'IP Renewals'
    WHEN service_type = 'incorp' THEN 'Incorporation'
    ELSE service_type
  END AS name,

  COALESCE(SUM(CASE WHEN progress = 100 THEN 1 ELSE 0 END), 0) AS completed,
  COALESCE(COUNT(*), 0) AS total,

  CASE 
    WHEN MAX(deadline) IS NULL THEN 'no-deadline'
    WHEN DATEDIFF(MAX(deadline), CURDATE()) < 0 THEN 'behind'
    WHEN DATEDIFF(MAX(deadline), CURDATE()) > 10 THEN 'ahead'
    ELSE 'on-track'
  END AS status,

  MAX(deadline) AS deadline
FROM services
GROUP BY service_type
ORDER BY 
  CASE 
    WHEN MAX(deadline) IS NULL THEN 4
    WHEN DATEDIFF(MAX(deadline), CURDATE()) < 0 THEN 1
    WHEN DATEDIFF(MAX(deadline), CURDATE()) > 10 THEN 3
    ELSE 2
  END,
  MAX(deadline) ASC;
`)
 res.json(rows);
  }
  catch(e){
    console.log("Error fetching service stats",e);
  }
});

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
    WHEN s.service_type = 'ip' THEN 'Trademark Renewal'
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

app.patch("/update_payment/:id", async (req, res) => {
  const client_id = req.params.id;
  const { total_payment, payment, deadline } = req.body;

  try {
    const total = parseFloat(total_payment);
    const paid = parseFloat(payment);

    const [result] = await db.query(
      `UPDATE billing 
       SET total_amount = ?, 
           amount_paid = ?, 
           due_date = ?, 
           status = get_billing_status(?, ?, ?) 
       WHERE client_id = ?`,
      [total, paid, deadline, paid, total, deadline, client_id]
    );

    res.json({ message: "Billing updated successfully", updated: result.affectedRows });
  } catch (err) {
    console.error("Error updating billing:", err);
    res.status(500).json({ error: "Failed to update billing" });
  }
});







const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
