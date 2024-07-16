const express = require('express');
const bodyParser = require('body-parser');
const admin = require('firebase-admin');
const bcrypt = require('bcrypt');
const saltRounds = 10;
const jwt = require('jsonwebtoken');
const cors = require('cors');
const nodemailer = require('nodemailer');
const moment = require('moment-timezone');

const app = express();
app.use(cors());
app.use(bodyParser.json());

const serviceAccount = JSON.parse(process.env.FIREBASE_ADMIN_CONFIG);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();

const generateAccessToken = (userId) => {
  return jwt.sign({ id: userId }, process.env.JWT_SECRET_KEY, { expiresIn: '1h' });
};

const generateRefreshToken = (userId) => {
  return jwt.sign({ id: userId }, process.env.JWT_REFRESH_SECRET_KEY, { expiresIn: '7d' });
};

const verifyToken = (req, res, next) => {
  const token = req.header('Authorization').replace('Bearer ', '');
  if (!token) {
    return res.status(401).send("Access denied. No token provided.");
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);
    req.user = decoded;
    next();
  } catch (ex) {
    res.status(400).send("Invalid token.");
  }
};

// Define routes here
//Registrasi Pengguna Baru
app.post('/auth/register', async (req, res) => {
  try {
    const { email, password, confirmPassword, username } = req.body;

    // Validasi input
    if (!email || !password || !confirmPassword || !username) {
      return res.status(400).send("Semua data wajib diisi.");
    }

    // Validasi format email
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).send("Format email yang anda masukkan tidak benar.");
    }

    // Mengecek apakah password dan confirmPassword cocok
    if (password !== confirmPassword) {
      return res.status(400).send("Kata sandi yang anda masukkan tidak cocok.");
    }

    // Mengecek apakah username sudah ada
    const usernameSnapshot = await db.collection('app_account').where('username', '==', username).get();
    if (!usernameSnapshot.empty) {
      return res.status(400).send("Username sudah digunakan oleh pengguna lain.");
    }

    // Mengecek apakah email sudah ada
    const emailSnapshot = await db.collection('app_account').where('email', '==', email).get();
    if (!emailSnapshot.empty) {
      return res.status(400).send("Email sudah digunakan oleh pengguna lain.");
    }

    // Enkripsi password sebelum menyimpan ke database
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Simpan user dengan password yang sudah dienkripsi
    const newUserRef = await db.collection('app_account').add({
      email: email,
      username: username,
      password: hashedPassword
    });

    res.status(201).send(`Sukses menambahkan user dengan ID: ${newUserRef.id}`);
  } catch (error) {
    res.status(400).send(error.message);
  }
});

//Login pengguna
app.post('/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).send("Username dan password harus diisi.");
    }

    // Cari user berdasarkan username
    const usersRef = db.collection('app_account');
    const snapshot = await usersRef.where('username', '==', username).get();
    if (snapshot.empty) {
      return res.status(401).send("Username tidak terdaftar.");
    }

    // Dapatkan data user
    let userId = '';
    let storedPassword = '';
    let userEmail = '';
    snapshot.forEach(doc => {
      userId = doc.id;
      storedPassword = doc.data().password;
      userEmail = doc.data().email;
    });

    // Verifikasi password
    const passwordMatch = await bcrypt.compare(password, storedPassword);
    if (!passwordMatch) {
      return res.status(401).send("Password yang anda masukkan salah.");
    }

    // Generate JWT and Refresh Token
    const accessToken = generateAccessToken(userId);
    const refreshToken = generateRefreshToken(userId);

    // Simpan refresh token ke database atau storage
    await db.collection('refresh_tokens').doc(userId).set({ refreshToken });

    res.status(200).send({
      message: "Berhasil login",
      username: username,
      email: userEmail,
      accessToken: accessToken,
      refreshToken: refreshToken
    });
  } catch (error) {
    res.status(500).send(error.message);
  }
});

// Endpoint logout
app.post('/auth/logout', verifyToken, async (req, res) => {
  try {
    const userId = req.user.id;

    // Hapus refresh token dari database atau storage
    await db.collection('refresh_tokens').doc(userId).delete();

    res.status(200).send({
      message: "Anda berhasil logout"
    });
  } catch (error) {
    res.status(500).send(error.message);
  }
});

// Endpoint untuk Memperbarui Token
app.post('/auth/token', async (req, res) => {
  const { token } = req.body;

  if (!token) {
    return res.status(401).send("Refresh token must be provided.");
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_REFRESH_SECRET_KEY);
    const userId = decoded.id;

    // Verifikasi apakah refresh token masih valid
    const refreshTokenDoc = await db.collection('refresh_tokens').doc(userId).get();
    if (!refreshTokenDoc.exists || refreshTokenDoc.data().refreshToken !== token) {
      return res.status(403).send("Invalid refresh token.");
    }

    // Generate new access token
    const newAccessToken = generateAccessToken(userId);

    res.status(200).send({ accessToken: newAccessToken });
  } catch (error) {
    res.status(403).send("Invalid refresh token.");
  }
});

// Mengedit profil user
app.put('/users/me', verifyToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const { email, username } = req.body;

    if (!email && !username) {
      return res.status(400).send("Setidaknya edit satu data.");
    }

    const userRef = db.collection('app_account').doc(userId);
    const userDoc = await userRef.get();

    if (!userDoc.exists) {
      return res.status(404).send("User tidak ditemukan.");
    }

    let updateData = {};
    if (email) updateData.email = email;
    if (username) updateData.username = username;

    await userRef.update(updateData);

    res.status(200).send({ message: "Berhasil edit data user", userId: userId });
  } catch (error) {
    res.status(500).send(error.message);
  }
});

// Mengubah password user
app.put('/users/me/password', verifyToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const { currentPassword, newPassword, confirmNewPassword } = req.body;

    if (!currentPassword || !newPassword || !confirmNewPassword) {
      return res.status(400).send("Semua data wajib diisi.");
    }

    if (newPassword !== confirmNewPassword) {
      return res.status(400).send("Kata sandi baru yang anda masukkan tidak cocok.");
    }

    // Dapatkan data user
    const userRef = db.collection('app_account').doc(userId);
    const userDoc = await userRef.get();

    if (!userDoc.exists) {
      return res.status(404).send("User tidak ditemukan.");
    }

    const storedPassword = userDoc.data().password;

    // Verifikasi current password
    const passwordMatch = await bcrypt.compare(currentPassword, storedPassword);
    if (!passwordMatch) {
      return res.status(401).send("Kata sandi lama yang anda masukkan salah.");
    }

    // Hash new password
    const hashedNewPassword = await bcrypt.hash(newPassword, 10);

    // Update password di database
    await userRef.update({ password: hashedNewPassword });

    res.status(200).send({ message: "Anda berhasil mengubah password" });
  } catch (error) {
    res.status(500).send(error.message);
  }
});

app.post('/nasabah', async (req, res) => {
  try {
    const { name, phoneNumber, address, email } = req.body;

    // Validasi input dasar
    if (!name || !phoneNumber || !address || !email) {
      return res.status(400).send("Semua data wajib diisi.");
    }

    // Verifikasi bahwa nomor telepon belum terdaftar (opsional)
    const existingCustomerByPhone = await db.collection('nasabah').where('phoneNumber', '==', phoneNumber).get();
    if (!existingCustomerByPhone.empty) {
      return res.status(400).send("Nomor sudah dipakai oleh nasabah lain.");
    }

    // Verifikasi bahwa nama nasabah belum terdaftar
    const existingCustomerByName = await db.collection('nasabah').where('name', '==', name).get();
    if (!existingCustomerByName.empty) {
      return res.status(400).send("Nama sudah dipakai oleh nasabah lain.");
    }

    // Verifikasi bahwa email belum terdaftar (opsional)
    const existingCustomerByEmail = await db.collection('nasabah').where('email', '==', email).get();
    if (!existingCustomerByEmail.empty) {
      return res.status(400).send("Email sudah dipakai oleh nasabah lain.");
    }

    // Simpan data nasabah ke database
    const newCustomerRef = await db.collection('nasabah').add({
      name: name,
      phoneNumber: phoneNumber,
      address: address,
      email: email
    });

    res.status(201).send({ message: "Berhasil registrasi nasabah baru", customerId: newCustomerRef.id });

  } catch (error) {
    res.status(500).send(error.message);
  }
});

//Mendapatkan seluruh data nasabah
app.get('/nasabah', async (req, res) => {
    try {
      const customersRef = db.collection('nasabah');
      const snapshot = await customersRef.get();
  
      if (snapshot.empty) {
        return res.status(404).send("Tidak ditemukan data nasabah.");
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

app.get('/jumlahnasabah', async (req, res) => {
  try {
      const customersRef = db.collection('nasabah');
      const snapshot = await customersRef.get();

      if (snapshot.empty) {
          return res.status(404).send("Tidak ditemukan data nasabah.");
      }

      const jumlahNasabah = snapshot.size; // Menghitung jumlah dokumen

      res.status(200).send({ jumlahNasabah });
  } catch (error) {
      res.status(500).send(error.message);
  }
});

// Mendapatkan detail data nasabah
app.get('/nasabah/:id', async (req, res) => {
  try {
    const customerId = req.params.id;

    // Ambil data nasabah berdasarkan ID
    const customerRef = db.collection('nasabah').doc(customerId);
    const customerDoc = await customerRef.get();

    if (!customerDoc.exists) {
      return res.status(404).send("Nasabah tidak terdaftar.");
    }

    let customerData = customerDoc.data();
    customerData.id = customerId;

    res.status(200).send(customerData);
  } catch (error) {
    res.status(500).send(error.message);
  }
});

//Mendapatkan nama nasabah dari daftar nasabah
app.get('/nasabah/names', async (req, res) => {
  try {
    const customersRef = db.collection('nasabah');
    const snapshot = await customersRef.get();

    if (snapshot.empty) {
      return res.status(404).send("Tidak ditemukan data nasabah.");
    }

    let customerNames = [];
    snapshot.forEach(doc => {
      customerNames.push(doc.data().name);
    });

    res.status(200).send(customerNames);
  } catch (error) {
    res.status(500).send(error.message);
  }
});

// Endpoint untuk Mencari Nasabah Berdasarkan Nama
app.get('/nasabah/search', async (req, res) => {
  try {
    const { name } = req.query;

    if (!name) {
      return res.status(400).send("Query paramater name harus diberikan.");
    }

    const customersRef = db.collection('nasabah');
    const snapshot = await customersRef.get();

    if (snapshot.empty) {
      console.log("No documents found in the collection.");
      return res.status(404).send("Tidak ditemukan data nasabah.");
    }

    const regex = new RegExp(name.split(' ').join('|'), 'i');
    let customers = [];
    snapshot.forEach(doc => {
      console.log("Checking document: ", doc.data());
      if (regex.test(doc.data().name)) {
        customers.push(doc.data());
      }
    });

    if (customers.length === 0) {
      console.log("No matching customers found.");
      return res.status(404).send("Nasabah yang anda cari tidak ada.");
    }

    res.status(200).send(customers);
  } catch (error) {
    console.error("Error occurred: ", error.message);
    res.status(500).send(error.message);
  }
});

// Mengedit data nasabah
app.put('/nasabah/:id', async (req, res) => {
  try {
    const customerId = req.params.id;
    const { name, phoneNumber, address, email } = req.body;

    // Validasi input dasar
    if (!name && !phoneNumber && !address && !email) {
      return res.status(400).send("Setidaknya edit satu data nasabah.");
    }

    // Ambil referensi dokumen nasabah berdasarkan ID
    const customerRef = db.collection('nasabah').doc(customerId);
    const customerDoc = await customerRef.get();

    if (!customerDoc.exists) {
      return res.status(404).send("Nasabah tidak ditemukan.");
    }

    // Buat objek update dengan hanya field yang diberikan
    let updateData = {};
    if (name) updateData.name = name;
    if (phoneNumber) updateData.phoneNumber = phoneNumber;
    if (address) updateData.address = address;
    if (email) updateData.email = email;

    // Update data nasabah di Firestore
    await customerRef.update(updateData);

    // Update nama dokumen di collection saldo_nasabah jika nama berubah
    if (name) {
      const oldName = customerDoc.data().name;
      const datasavingRef = db.collection('saldo_nasabah').doc(oldName);
      const datasavingDoc = await datasavingRef.get();

      if (datasavingDoc.exists) {
        const { totalBalance } = datasavingDoc.data();

        // Buat dokumen baru dengan nama baru dan totalBalance yang sama
        await db.collection('saldo_nasabah').doc(name).set({
          name: name,
          totalBalance: totalBalance
        });

        // Hapus dokumen lama
        await datasavingRef.delete();
      }
    }

    res.status(200).send({ message: "Berhasil mengedit data nasabah", customerId: customerId });
  } catch (error) {
    res.status(500).send(error.message);
  }
});

// Menghapus data nasabah
app.delete('/nasabah/:id', async (req, res) => {
  try {
    const customerId = req.params.id;

    // Ambil referensi dokumen nasabah berdasarkan ID
    const customerRef = db.collection('nasabah').doc(customerId);
    const customerDoc = await customerRef.get();

    if (!customerDoc.exists) {
      return res.status(404).send("Nasabah tidak terdaftar.");
    }

    // Ambil nama nasabah untuk digunakan sebagai referensi ID saldo
    const customerName = customerDoc.data().name;

    // Hapus dokumen nasabah dari Firestore
    await customerRef.delete();

    // Ambil referensi dokumen saldo nasabah berdasarkan nama nasabah
    const saldoRef = db.collection('saldo_nasabah').doc(customerName);
    const saldoDoc = await saldoRef.get();

    if (saldoDoc.exists) {
      // Hapus dokumen saldo nasabah yang sesuai
      await saldoRef.delete();
    }

    res.status(200).send({ message: "Berhasil menghapus data nasabah dan saldo yang sesuai", customerId: customerId });
  } catch (error) {
    res.status(500).send(error.message);
  }
});

//Menambahkan jenis sampah
app.post('/wastetypes', async (req, res) => {
    try {
      const { name, pricePer100Gram } = req.body;
  
      // Validasi input dasar
      if (!name || !pricePer100Gram) {
        return res.status(400).send("Semua data jenis sampah wajib diisi.");
      }
  
      // Simpan data jenis sampah ke database
      const newWasteTypeRef = await db.collection('jenis_sampah').add({
        name: name,
        pricePer100Gram: pricePer100Gram
      });
  
      res.status(201).send({ message: "Berhasil menambahkan jenis sampah", wasteTypeId: newWasteTypeRef.id });
  
    } catch (error) {
      res.status(500).send(error.message);
    }
});

// Mendapatkan data jenis sampah
app.get('/wastetypes', async (req, res) => {
  try {
    // Mengambil semua data jenis sampah dari koleksi 'waste_types'
    const wasteTypesRef = db.collection('jenis_sampah');
    const snapshot = await wasteTypesRef.get();

    if (snapshot.empty) {
      return res.status(404).send("Tidak ada jenis sampah.");
    }

    let wasteTypes = [];
    snapshot.forEach(doc => {
      let wasteTypeData = doc.data();
      // Menambahkan ID jenis sampah ke dalam data jenis sampah
      wasteTypeData.id = doc.id;
      wasteTypes.push(wasteTypeData);
    });

    res.status(200).send(wasteTypes);
  } catch (error) {
    res.status(500).send(error.message);
  }
});

// Endpoint untuk Mencari Jenis Sampah Berdasarkan Nama
app.get('/wastetypes/search', async (req, res) => {
  try {
    const { name } = req.query;

    if (!name) {
      return res.status(400).send("Query paramater name harus diberikan.");
    }

    const wasteTypesRef = db.collection('jenis_sampah');
    const snapshot = await wasteTypesRef.where('name', '==', name).get();

    if (snapshot.empty) {
      return res.status(404).send("Tidak ada jenis sampah yang anda cari.");
    }

    let wasteTypes = [];
    snapshot.forEach(doc => {
      wasteTypes.push(doc.data());
    });

    res.status(200).send(wasteTypes);
  } catch (error) {
    res.status(500).send(error.message);
  }
});

// Mengedit data jenis sampah
app.put('/wastetypes/:id', async (req, res) => {
  try {
    const wasteTypeId = req.params.id;
    const { name, pricePer100Gram } = req.body;

    // Validasi input dasar
    if (!name && !pricePer100Gram) {
      return res.status(400).send("Setidaknya edit satu data.");
    }

    // Ambil referensi dokumen jenis sampah berdasarkan ID
    const wasteTypeRef = db.collection('jenis_sampah').doc(wasteTypeId);
    const wasteTypeDoc = await wasteTypeRef.get();

    if (!wasteTypeDoc.exists) {
      return res.status(404).send("Jenis sampah tidak ditemukan.");
    }

    // Buat objek update dengan hanya field yang diberikan
    let updateData = {};
    if (name) updateData.name = name;
    if (pricePer100Gram) updateData.pricePer100Gram = pricePer100Gram;

    // Update data jenis sampah di Firestore
    await wasteTypeRef.update(updateData);

    res.status(200).send({ message: "Berhasil mengedit jenis sampah", wasteTypeId: wasteTypeId });
  } catch (error) {
    res.status(500).send(error.message);
  }
});

// Menghapus jenis sampah
app.delete('/wastetypes/:id', async (req, res) => {
  try {
    const wasteTypeId = req.params.id;

    // Ambil referensi dokumen jenis sampah berdasarkan ID
    const wasteTypeRef = db.collection('jenis_sampah').doc(wasteTypeId);
    const wasteTypeDoc = await wasteTypeRef.get();

    if (!wasteTypeDoc.exists) {
      return res.status(404).send("Jenis sampah tidak ditemukan.");
    }

    // Hapus dokumen jenis sampah dari Firestore
    await wasteTypeRef.delete();

    res.status(200).send({ message: "Berhasil menghapus jenis sampah", wasteTypeId: wasteTypeId });
  } catch (error) {
    res.status(500).send(error.message);
  }
});

app.post('/jualsampah', async (req, res) => {
  try {
      const { wasteTypeId, amount, note } = req.body;

      // Validasi input
      if (!wasteTypeId || amount == null || isNaN(amount) || amount <= 0) {
          return res.status(400).send("Jenis sampah dan jumlah sampah yang valid wajib diisi.");
      }

      if (!note || typeof note !== 'string') {
          return res.status(400).send("Catatan wajib diisi dengan format teks yang valid.");
      }

      // Ambil data jenis sampah dari koleksi 'jumlah_sampah'
      const wasteAmountRef = db.collection('jumlah_sampah').doc(wasteTypeId);
      const wasteAmountDoc = await wasteAmountRef.get();

      if (!wasteAmountDoc.exists) {
          return res.status(404).send("Jenis sampah tidak ditemukan.");
      }

      const wasteAmountData = wasteAmountDoc.data();
      const currentAmount = wasteAmountData.totalAmount;

      // Periksa apakah jumlah sampah cukup untuk dikurangi
      if (currentAmount < amount) {
          return res.status(400).send("Jumlah sampah tidak mencukupi untuk pengurangan.");
      }

      // Kurangi jumlah sampah
      const newAmount = currentAmount - amount;
      await wasteAmountRef.update({
          totalAmount: newAmount
      });

      const currentDate = moment().tz('Asia/Jakarta').format();

      // Simpan data pengurangan ke koleksi 'waste_reductions'
      await db.collection('waste_reductions').add({
          wasteTypeId: wasteTypeId,
          amount: amount,
          note: note,
          date: currentDate
      });

      res.status(201).send({ message: "Pengurangan jumlah sampah berhasil", newAmount: newAmount });

  } catch (error) {
      res.status(500).send(error.message);
  }
});

// Menabung sampah
app.post('/tabung', async (req, res) => {
  try {
      const { name, date, deposits } = req.body;

      // Validasi input dasar
      if (!name || !date || !deposits || !Array.isArray(deposits) || deposits.length === 0) {
          return res.status(400).send("Semua data wajib diisi.");
      }

      // Ambil data nasabah untuk mendapatkan email
      const nasabahRef = db.collection('nasabah').where('name', '==', name);
      const nasabahSnapshot = await nasabahRef.get();

      if (nasabahSnapshot.empty) {
          return res.status(404).send("Nasabah tidak ditemukan.");
      }

      let email;
      nasabahSnapshot.forEach(doc => {
          email = doc.data().email;
      });

      if (!email) {
          return res.status(400).send("Email nasabah tidak ditemukan.");
      }

      // Membuat variabel untuk total saldo
      let totalBalance = 0;

      // Membuat objek untuk menyimpan jumlah sampah berdasarkan jenis dan nama jenis sampah
      let wasteAmounts = {};
      let wasteNames = {};

      // Iterasi melalui setiap entri deposit
      for (const tabung of deposits) {
          const { wasteTypeId, amount } = tabung;

          // Validasi input untuk setiap entri deposit
          if (!wasteTypeId || amount == null || isNaN(amount) || amount <= 0) {
              return res.status(400).send("Setidaknya masukkan 1 jenis sampah dengan jumlah yang valid.");
          }

          // Dapatkan harga per 100 gram dan nama dari jenis sampah yang sesuai
          const wasteTypeDoc = await db.collection('jenis_sampah').doc(wasteTypeId).get();
          if (!wasteTypeDoc.exists) {
              return res.status(404).send(`Jenis sampah ${wasteTypeId} tidak ada.`);
          }

          const wasteTypeData = wasteTypeDoc.data();
          const pricePer100Gram = wasteTypeData.pricePer100Gram;
          const wasteTypeName = wasteTypeData.name;

          // Konversi jumlah dari kg ke 100 gram dan hitung total saldo untuk jenis sampah ini
          const amountInHundredGrams = (amount * 1000) / 100;
          totalBalance += pricePer100Gram * amountInHundredGrams;

          // Tambahkan jumlah ke wasteAmounts dan nama jenis sampah ke wasteNames
          if (wasteAmounts[wasteTypeId]) {
              wasteAmounts[wasteTypeId] += amount;
          } else {
              wasteAmounts[wasteTypeId] = amount;
              wasteNames[wasteTypeId] = wasteTypeName;
          }
      }

      // Simpan data transaksi ke koleksi 'transaksi' di Firestore
      const newTransactionRef = await db.collection('transaksi').add({
          name: name,
          date: date,
          deposits: deposits,
          totalBalance: totalBalance
      });

      // Update atau tambahkan data nasabah ke koleksi 'saldo_nasabah' di Firestore
      const customerRef = db.collection('saldo_nasabah').doc(name);
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

      // Update jumlah sampah berdasarkan jenis di koleksi 'jumlah_sampah'
      for (const wasteTypeId in wasteAmounts) {
          const wasteAmount = wasteAmounts[wasteTypeId];
          const wasteAmountRef = db.collection('jumlah_sampah').doc(wasteTypeId);
          const wasteAmountDoc = await wasteAmountRef.get();

          if (wasteAmountDoc.exists) {
              // Jika data jenis sampah sudah ada, update jumlahnya
              const existingAmount = wasteAmountDoc.data().totalAmount || 0;
              await wasteAmountRef.update({
                  totalAmount: existingAmount + wasteAmount
              });
          } else {
              // Jika data jenis sampah belum ada, tambahkan data baru
              await wasteAmountRef.set({
                  wasteTypeId: wasteTypeId,
                  totalAmount: wasteAmount
              });
          }
      }

      // Mengirim email nota elektronik
      let transporter = nodemailer.createTransport({
          service: 'hotmail',
          auth: {
              user: process.env.EMAIL_SECRET_KEY,
              pass: process.env.PASS_SECRET_KEY
          }
      });

      let mailOptions = {
          from: process.env.EMAIL_SECRET_KEY,
          to: email,
          subject: 'Nota Menabung Sampah - WasteApp',
          html: `<h3>Data Transaksi Menabung Sampah</h3>
                 --------------------------------------- 
                 <p>Nama: ${name}</p>
                 <p>Tanggal: ${date}</p>
                 <p>Deposits:</p>
                 <ul>
                   ${Object.keys(wasteAmounts).map(wasteTypeId => `<li>Jenis Sampah: ${wasteNames[wasteTypeId]}, Jumlah: ${wasteAmounts[wasteTypeId]} kg</li>`).join('')}
                 </ul>
                 ---------------------------------------
                 <p>Saldo Masuk: ${totalBalance}</p>
                 <p>-- Terimakasih sudah menabung di bank sampah WasteApp -- </p>`
      };

      await transporter.sendMail(mailOptions);

      res.status(201).send({ message: "Berhasil menabung sampah dan nota elektronik telah dikirimkan", transactionId: newTransactionRef.id });

  } catch (error) {
      res.status(500).send(error.message);
  }
});

app.get('/stoksampah', async (req, res) => {
  try {
      // Ambil semua data dari koleksi 'jumlah_sampah'
      const jumlahSampahSnapshot = await db.collection('jumlah_sampah').get();
      if (jumlahSampahSnapshot.empty) {
          return res.status(404).send("Tidak ada data di koleksi jumlah_sampah.");
      }

      // Buat array untuk menampung data
      let jumlahSampahData = [];
      jumlahSampahSnapshot.forEach(doc => {
          jumlahSampahData.push({ id: doc.id, ...doc.data() });
      });

      res.status(200).send(jumlahSampahData);
  } catch (error) {
      res.status(500).send(error.message);
  }
});

app.get('/totalstoksampah', async (req, res) => {
  try {
      // Ambil semua data dari koleksi 'jumlah_sampah'
      const jumlahSampahSnapshot = await db.collection('jumlah_sampah').get();
      if (jumlahSampahSnapshot.empty) {
          return res.status(404).send("Tidak ada data di koleksi jumlah_sampah.");
      }

      // Hitung total stok sampah
      let totalStokSampah = 0;
      jumlahSampahSnapshot.forEach(doc => {
          const data = doc.data();
          if (data.totalAmount && !isNaN(data.totalAmount)) {
              totalStokSampah += data.totalAmount;
          }
      });

      res.status(200).send({ totalStokSampah });
  } catch (error) {
      res.status(500).send(error.message);
  }
});

app.get('/stoksampahkeluar', async (req, res) => {
  try {
      // Ambil semua data dari koleksi 'waste_reductions'
      const wasteReductionsSnapshot = await db.collection('waste_reductions').get();
      if (wasteReductionsSnapshot.empty) {
          return res.status(404).send("Tidak ada data di koleksi waste_reductions.");
      }

      // Buat array untuk menampung data
      let wasteReductionsData = [];
      wasteReductionsSnapshot.forEach(doc => {
          wasteReductionsData.push({ id: doc.id, ...doc.data() });
      });

      res.status(200).send(wasteReductionsData);
  } catch (error) {
      res.status(500).send(error.message);
  }
});

app.post('/tariksaldo', async (req, res) => {
  try {
      const { name, amount, note } = req.body;

      // Validasi input
      if (!name || amount == null || isNaN(amount) || amount <= 0) {
          return res.status(400).send("Nama nasabah dan jumlah penarikan yang valid wajib diisi.");
      }

      if (!note || typeof note !== 'string') {
          return res.status(400).send("Catatan wajib diisi dengan format teks yang valid.");
      }

      // Ambil data nasabah dari koleksi 'saldo_nasabah'
      const customerRef = db.collection('saldo_nasabah').doc(name);
      const customerDoc = await customerRef.get();

      if (!customerDoc.exists) {
          return res.status(404).send("Nasabah tidak ditemukan.");
      }

      const customerData = customerDoc.data();
      const currentBalance = customerData.totalBalance;

      // Periksa apakah saldo cukup untuk penarikan
      if (currentBalance < amount) {
          return res.status(400).send("Saldo tidak mencukupi untuk penarikan.");
      }

      // Kurangi saldo nasabah
      const newBalance = currentBalance - amount;
      await customerRef.update({
          totalBalance: newBalance
      });

      const currentDate = moment().tz('Asia/Jakarta').format();

      // Simpan data penarikan ke koleksi 'saldo_keluar'
      const withdrawalRef = await db.collection('saldo_keluar').add({
          name: name,
          amount: amount,
          note: note,
          date: currentDate
      });

      // Ambil data nasabah untuk mendapatkan email
      const nasabahRef = db.collection('nasabah').where('name', '==', name);
      const nasabahSnapshot = await nasabahRef.get();

      if (nasabahSnapshot.empty) {
          return res.status(404).send("Nasabah tidak ditemukan.");
      }

      let email;
      nasabahSnapshot.forEach(doc => {
          email = doc.data().email;
      });

      if (!email) {
          return res.status(400).send("Email nasabah tidak ditemukan.");
      }

      // Mengirim email nota penarikan saldo
      let transporter = nodemailer.createTransport({
          service: 'hotmail',
          auth: {
              user: process.env.EMAIL_SECRET_KEY,
              pass: process.env.PASS_SECRET_KEY
          }
      });

      let mailOptions = {
          from: process.env.EMAIL_SECRET_KEY,
          to: email,
          subject: 'Nota Penarikan Saldo Bank Sampah',
          html: `<h3>Nota Tarik Saldo Nasabah</h3>
                 <p>Nama: ${name}</p>
                 <p>Tanggal: ${new Date().toISOString()}</p>
                 <p>Jumlah Penarikan: ${amount}</p>
                 <p>Catatan: ${note}</p>
                 <p>Sisa Saldo: ${newBalance}</p>`
      };

      await transporter.sendMail(mailOptions);

      res.status(201).send({ message: "Penarikan saldo berhasil dan nota elektronik telah dikirimkan", newBalance: newBalance });

  } catch (error) {
      res.status(500).send(error.message);
  }
});

app.get('/saldokeluar', async (req, res) => {
  try {
      // Ambil semua data dari koleksi 'saldo_keluar'
      const saldoKeluarSnapshot = await db.collection('saldo_keluar').get();
      if (saldoKeluarSnapshot.empty) {
          return res.status(404).send("Tidak ada data di koleksi saldo_keluar.");
      }

      // Buat array untuk menampung data
      let saldoKeluarData = [];
      saldoKeluarSnapshot.forEach(doc => {
          saldoKeluarData.push({ id: doc.id, ...doc.data() });
      });

      res.status(200).send(saldoKeluarData);
  } catch (error) {
      res.status(500).send(error.message);
  }
});

app.get('/saldo', async (req, res) => {
  try {
    const saldoRef = db.collection('saldo_nasabah');
    const snapshot = await saldoRef.get();

    if (snapshot.empty) {
      return res.status(404).send("Tidak ditemukan data saldo nasabah.");
    }

    let saldo = [];
    snapshot.forEach(doc => {
      let customerData = doc.data();
      customerData.id = doc.id; // Menambahkan ID document ke data nasabah
      saldo.push(customerData);
    });

    res.status(200).send(saldo);
  } catch (error) {
    res.status(500).send(error.message);
  }
});

app.get('/totalsaldo', async (req, res) => {
  try {
      const saldoRef = db.collection('saldo_nasabah');
      const snapshot = await saldoRef.get();

      if (snapshot.empty) {
          return res.status(404).send("Tidak ditemukan data saldo nasabah.");
      }

      let totalSaldo = 0;
      snapshot.forEach(doc => {
          const customerData = doc.data();
          if (customerData.totalBalance && !isNaN(customerData.totalBalance)) {
              totalSaldo += customerData.totalBalance;
          }
      });

      res.status(200).send({ totalSaldo });
  } catch (error) {
      res.status(500).send(error.message);
  }
});

//Mendapatkan data tabung
app.get('/tabung', async (req, res) => {
  try {
    // Mengambil semua data transaksi dari koleksi 'transactions'
    const transactionsRef = db.collection('transaksi');
    const snapshot = await transactionsRef.get();

    if (snapshot.empty) {
      return res.status(404).send("Tidak ditemukan data transaksi menabung.");
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

// app.get('/rekapantransaksi', async (req, res) => {
//   try {
//     const { period } = req.query;
//     const transactionsRef = db.collection('transaksi');
//     const snapshot = await transactionsRef.get();

//     if (snapshot.empty) {
//       return res.status(404).send("Tidak ditemukan data transaksi menabung.");
//     }

//     let startDate;
//     const today = moment().startOf('day');
//     const startOfWeek = moment().startOf('week');
//     const startOfMonth = moment().startOf('month');

//     if (period === 'today') {
//       startDate = today;
//     } else if (period === 'week') {
//       startDate = startOfWeek;
//     } else if (period === 'month') {
//       startDate = startOfMonth;
//     } else {
//       return res.status(400).send("Parameter periode tidak valid. Gunakan 'today', 'week', atau 'month'.");
//     }

//     let totalAmount = 0;

//     snapshot.forEach(doc => {
//       const transactionData = doc.data();
//       const transactionDate = moment(transactionData.date, 'DD/MM/YYYY');

//       if (transactionDate.isSameOrAfter(startDate)) {
//         totalAmount += transactionData.amount;
//       }
//     });

//     const response = {
//       period,
//       totalAmount,
//     };

//     res.status(200).send(response);
//   } catch (error) {
//     res.status(500).send(error.message);
//   }
// });

// Mendapatkan detail data dari riwayat tabung
app.get('/tabung/:id', async (req, res) => {
  try {
    const transactionId = req.params.id;

    // Ambil data transaksi berdasarkan ID
    const transactionRef = db.collection('transaksi').doc(transactionId);
    const transactionDoc = await transactionRef.get();

    if (!transactionDoc.exists) {
      return res.status(404).send("Tidak ditemukan data transaksi ini.");
    }

    let transactionData = transactionDoc.data();
    transactionData.id = transactionId; // Tambahkan ID transaksi ke dalam data transaksi

    res.status(200).send(transactionData);
  } catch (error) {
    res.status(500).send(error.message);
  }
});
  
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
