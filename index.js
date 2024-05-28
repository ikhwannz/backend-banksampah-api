const express = require('express');
const bodyParser = require('body-parser');
const admin = require('firebase-admin');
const bcrypt = require('bcrypt');
const saltRounds = 10;

const app = express();
app.use(bodyParser.json());

const serviceAccount = JSON.parse(process.env.FIREBASE_ADMIN_CONFIG);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();

// Define routes here
//Registrasi Pengguna Baru
app.post('/auth/register', async (req, res) => {
  try {
    const { email, password, confirmPassword, username } = req.body;

    // Validasi input dasar
    if (!email || !password || !confirmPassword || !username) {
      return res.status(400).send("All fields (email, password, confirm password, and username) are required.");
    }

    // Cek apakah password dan confirmPassword cocok
    if (password !== confirmPassword) {
      return res.status(400).send("Passwords do not match.");
    }

    // Enkripsi password sebelum menyimpan ke database
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Simpan user dengan password yang sudah dienkripsi
    const newUserRef = await db.collection('users').add({
      email: email,
      username: username,
      password: hashedPassword
    });

    res.status(201).send(`User added with ID: ${newUserRef.id}`);
  } catch (error) {
    res.status(400).send(error.message);
  }
});

//Login pengguna
app.post('/auth/login', async (req, res) => {
    try {
      const { username, password } = req.body;
  
      if (!username || !password) {
        return res.status(400).send("Username and password must be provided.");
      }
  
      // Cari user berdasarkan username
      const usersRef = db.collection('users');
      const snapshot = await usersRef.where('username', '==', username).get();
      if (snapshot.empty) {
        return res.status(401).send("Invalid credentials.");
      }
  
      // Dapatkan data user
      let userId = '';
      let storedPassword = '';
      snapshot.forEach(doc => {
        userId = doc.id;
        storedPassword = doc.data().password;
      });
  
      // Verifikasi password
      const passwordMatch = await bcrypt.compare(password, storedPassword);
      if (!passwordMatch) {
        return res.status(401).send("Invalid credentials.");
      }
  
      // Jika login berhasil, kirimkan respons sukses
      // Anda mungkin ingin mengimplementasikan pembuatan token JWT atau mekanisme sesi di sini
      res.status(200).send({ message: "Login successful", userId: userId });
  
    } catch (error) {
      res.status(500).send(error.message);
    }
});

//Mendaftarkan nasabah baru ahay
app.post('/customers', async (req, res) => {
    try {
      const { name, phoneNumber, address } = req.body;
  
      // Validasi input dasar
      if (!name || !phoneNumber || !address) {
        return res.status(400).send("All fields (name, phoneNumber, and address) are required.");
      }
  
      // Verifikasi bahwa nomor telepon belum terdaftar (opsional)
      const existingCustomer = await db.collection('customers').where('phoneNumber', '==', phoneNumber).get();
      if (!existingCustomer.empty) {
        return res.status(400).send("A customer with this phone number already exists.");
      }
  
      // Simpan data nasabah ke database
      const newCustomerRef = await db.collection('customers').add({
        name: name,
        phoneNumber: phoneNumber,
        address: address
      });
  
      res.status(201).send({ message: "Customer registered successfully", customerId: newCustomerRef.id });
  
    } catch (error) {
      res.status(500).send(error.message);
    }
});

//Mendapatkan seluruh data nasabah
app.get('/customers', async (req, res) => {
    try {
      const customersRef = db.collection('customers');
      const snapshot = await customersRef.get();
  
      if (snapshot.empty) {
        return res.status(404).send("No customers found.");
      }
  
      let customers = [];
      snapshot.forEach(doc => {
        let customerData = doc.data();
        customerData.id = doc.id; // Menambahkan ID document ke data nasabah
        customers.push(customerData);
      });
  
      res.status(200).send(customers);
    } catch (error) {
      res.status(500).send(error.message);
    }
});

// Mendapatkan detail data nasabah
app.get('/customers/:id', async (req, res) => {
  try {
    const customerId = req.params.id;

    // Ambil data nasabah berdasarkan ID
    const customerRef = db.collection('customers').doc(customerId);
    const customerDoc = await customerRef.get();

    if (!customerDoc.exists) {
      return res.status(404).send("Customer not found.");
    }

    let customerData = customerDoc.data();
    customerData.id = customerId;

    res.status(200).send(customerData);
  } catch (error) {
    res.status(500).send(error.message);
  }
});

//Mendapatkan nama nasabah dari daftar nasabah
app.get('/customers/names', async (req, res) => {
    try {
      const customersRef = db.collection('customers');
      const snapshot = await customersRef.get();
  
      if (snapshot.empty) {
        return res.status(404).send("No customers found.");
      }
  
      let customerNames = [];
      snapshot.forEach(doc => {
        let customerData = doc.data();
        customerNames.push(customerData.name); // Menambahkan hanya nama ke dalam array
      });
  
      res.status(200).send(customerNames);
    } catch (error) {
      res.status(500).send(error.message);
    }
});

// Mengedit data nasabah
app.put('/customers/:id', async (req, res) => {
  try {
    const customerId = req.params.id;
    const { name, phoneNumber, address } = req.body;

    // Validasi input dasar
    if (!name && !phoneNumber && !address) {
      return res.status(400).send("At least one field (name, phoneNumber, or address) is required.");
    }

    // Ambil referensi dokumen nasabah berdasarkan ID
    const customerRef = db.collection('customers').doc(customerId);
    const customerDoc = await customerRef.get();

    if (!customerDoc.exists) {
      return res.status(404).send("Customer not found.");
    }

    // Buat objek update dengan hanya field yang diberikan
    let updateData = {};
    if (name) updateData.name = name;
    if (phoneNumber) updateData.phoneNumber = phoneNumber;
    if (address) updateData.address = address;

    // Update data nasabah di Firestore
    await customerRef.update(updateData);

    res.status(200).send({ message: "Customer data updated successfully", customerId: customerId });
  } catch (error) {
    res.status(500).send(error.message);
  }
});

// Menghapus data nasabah
app.delete('/customers/:id', async (req, res) => {
  try {
    const customerId = req.params.id;

    // Ambil referensi dokumen nasabah berdasarkan ID
    const customerRef = db.collection('customers').doc(customerId);
    const customerDoc = await customerRef.get();

    if (!customerDoc.exists) {
      return res.status(404).send("Customer not found.");
    }

    // Hapus dokumen nasabah dari Firestore
    await customerRef.delete();

    res.status(200).send({ message: "Customer deleted successfully", customerId: customerId });
  } catch (error) {
    res.status(500).send(error.message);
  }
});

//Menambahkan jenis sampah
app.post('/wastetypes', async (req, res) => {
    try {
      const { name, pricePerKg } = req.body;
  
      // Validasi input dasar
      if (!name || !pricePerKg) {
        return res.status(400).send("Both name and price per kg are required.");
      }
  
      // Simpan data jenis sampah ke database
      const newWasteTypeRef = await db.collection('waste_types').add({
        name: name,
        pricePerKg: pricePerKg
      });
  
      res.status(201).send({ message: "Waste type added successfully", wasteTypeId: newWasteTypeRef.id });
  
    } catch (error) {
      res.status(500).send(error.message);
    }
});

//Menabung sampah
app.post('/transactions/deposit', async (req, res) => {
    try {
      const { name, date, deposits } = req.body;
  
      // Validasi input dasar
      if (!name || !date || !deposits || !Array.isArray(deposits) || deposits.length === 0) {
        return res.status(400).send("Name, date, and at least one deposit entry are required.");
      }
  
      // Membuat variabel untuk total saldo
      let totalBalance = 0;
  
      // Iterasi melalui setiap entri deposit
      for (const tabung of deposits) {
        const { wasteTypeId, amount } = tabung;
  
        // Validasi input untuk setiap entri deposit
        if (!wasteTypeId || !amount || isNaN(amount) || amount <= 0) {
          return res.status(400).send("Invalid deposit entry.");
        }
  
        // Dapatkan harga per kg dari jenis sampah yang sesuai
        const wasteTypeDoc = await db.collection('waste_types').doc(wasteTypeId).get();
        if (!wasteTypeDoc.exists) {
          return res.status(404).send(`Waste type with ID ${wasteTypeId} not found.`);
        }
  
        const wasteTypeData = wasteTypeDoc.data();
        const pricePerKg = wasteTypeData.pricePerKg;
  
        // Hitung total saldo untuk jenis sampah ini dan tambahkan ke total saldo keseluruhan
        totalBalance += pricePerKg * amount;
      }
  
      // Simpan data transaksi ke koleksi 'transactions' di Firestore
      const newTransactionRef = await db.collection('transactions').add({
        name: name,
        date: date,
        deposits: deposits,
        totalBalance: totalBalance
      });
  
      // Update atau tambahkan data nasabah ke koleksi 'customers' di Firestore
      const customerRef = db.collection('datasaving').doc(name);
      const customerDoc = await customerRef.get();
  
      if (customerDoc.exists) {
        // Jika nasabah sudah ada, update total saldo
        const existingBalance = customerDoc.data().totalBalance || 0;
        await customerRef.update({
          totalBalance: existingBalance + totalBalance
        });
      } else {
        // Jika nasabah belum ada, tambahkan data nasabah baru
        await customerRef.set({
          name: name,
          totalBalance: totalBalance
        });
      }
  
      res.status(201).send({ message: "Deposit transaction added successfully", transactionId: newTransactionRef.id });
  
    } catch (error) {
      res.status(500).send(error.message);
    }
});
  
//Mendapatkan data tabung
app.get('/transactions', async (req, res) => {
  try {
    // Mengambil semua data transaksi dari koleksi 'transactions'
    const transactionsRef = db.collection('transactions');
    const snapshot = await transactionsRef.get();

    if (snapshot.empty) {
      return res.status(404).send("No transactions found.");
    }

    let transactions = [];
    snapshot.forEach(doc => {
      let transactionData = doc.data();
      // Menambahkan ID transaksi ke dalam data transaksi
      transactionData.id = doc.id;
      transactions.push(transactionData);
    });

    res.status(200).send(transactions);
  } catch (error) {
    res.status(500).send(error.message);
  }
});

  
  
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
