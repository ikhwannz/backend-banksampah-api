const express = require('express');
const bodyParser = require('body-parser');
const admin = require('firebase-admin');
const bcrypt = require('bcrypt');
const saltRounds = 10;
const jwt = require('jsonwebtoken');
const cors = require('cors');

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

    // Mengecek apakah password dan confirmPassword cocok
    if (password !== confirmPassword) {
      return res.status(400).send("Kata sandi tidak cocok.");
    }

    // Enkripsi password sebelum menyimpan ke database
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Simpan user dengan password yang sudah dienkripsi
    const newUserRef = await db.collection('users').add({
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
    const usersRef = db.collection('users');
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
      message: "Berhasil logout"
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

    const userRef = db.collection('users').doc(userId);
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
      return res.status(400).send("Password baru dan konfirmasi password baru tidak cocok.");
    }

    // Dapatkan data user
    const userRef = db.collection('users').doc(userId);
    const userDoc = await userRef.get();

    if (!userDoc.exists) {
      return res.status(404).send("User tidak ditemukan.");
    }

    const storedPassword = userDoc.data().password;

    // Verifikasi current password
    const passwordMatch = await bcrypt.compare(currentPassword, storedPassword);
    if (!passwordMatch) {
      return res.status(401).send("Kata sandi saat ini salah.");
    }

    // Hash new password
    const hashedNewPassword = await bcrypt.hash(newPassword, 10);

    // Update password di database
    await userRef.update({ password: hashedNewPassword });

    res.status(200).send({ message: "Berhasil mengubah password" });
  } catch (error) {
    res.status(500).send(error.message);
  }
});

//Mendaftarkan nasabah baru
app.post('/nasabah', async (req, res) => {
    try {
      const { name, phoneNumber, address } = req.body;
  
      // Validasi input dasar
      if (!name || !phoneNumber || !address) {
        return res.status(400).send("Semua data wajib diisi.");
      }
  
      // Verifikasi bahwa nomor telepon belum terdaftar (opsional)
      const existingCustomer = await db.collection('customers').where('phoneNumber', '==', phoneNumber).get();
      if (!existingCustomer.empty) {
        return res.status(400).send("Nomor sudah dipakai oleh nasabah lain.");
      }
  
      // Simpan data nasabah ke database
      const newCustomerRef = await db.collection('customers').add({
        name: name,
        phoneNumber: phoneNumber,
        address: address
      });
  
      res.status(201).send({ message: "Berhasil mendaftarkan nasabah baru", customerId: newCustomerRef.id });
  
    } catch (error) {
      res.status(500).send(error.message);
    }
});

//Mendapatkan seluruh data nasabah
app.get('/nasabah', async (req, res) => {
    try {
      const customersRef = db.collection('customers');
      const snapshot = await customersRef.get();
  
      if (snapshot.empty) {
        return res.status(404).send("Tidak ada nasabah.");
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
app.get('/nasabah/:id', async (req, res) => {
  try {
    const customerId = req.params.id;

    // Ambil data nasabah berdasarkan ID
    const customerRef = db.collection('customers').doc(customerId);
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
    const customersRef = db.collection('customers');
    const snapshot = await customersRef.get();

    if (snapshot.empty) {
      return res.status(404).send("Nasabah tidak terdaftar.");
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

    const customersRef = db.collection('customers');
    const snapshot = await customersRef.get();

    if (snapshot.empty) {
      console.log("No documents found in the collection.");
      return res.status(404).send("No customers found.");
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
    const { name, phoneNumber, address } = req.body;

    // Validasi input dasar
    if (!name && !phoneNumber && !address) {
      return res.status(400).send("Setidaknya edit satu data. ");
    }

    // Ambil referensi dokumen nasabah berdasarkan ID
    const customerRef = db.collection('customers').doc(customerId);
    const customerDoc = await customerRef.get();

    if (!customerDoc.exists) {
      return res.status(404).send("Nasabah tidak ditemukan.");
    }

    // Buat objek update dengan hanya field yang diberikan
    let updateData = {};
    if (name) updateData.name = name;
    if (phoneNumber) updateData.phoneNumber = phoneNumber;
    if (address) updateData.address = address;

    // Update data nasabah di Firestore
    await customerRef.update(updateData);

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
    const customerRef = db.collection('customers').doc(customerId);
    const customerDoc = await customerRef.get();

    if (!customerDoc.exists) {
      return res.status(404).send("Nasabah tidak terdaftar.");
    }

    // Hapus dokumen nasabah dari Firestore
    await customerRef.delete();

    res.status(200).send({ message: "Berhasil menghapus data nasabah", customerId: customerId });
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
        return res.status(400).send("Semua data wajib diisi.");
      }
  
      // Simpan data jenis sampah ke database
      const newWasteTypeRef = await db.collection('waste_types').add({
        name: name,
        pricePerKg: pricePerKg
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
    const wasteTypesRef = db.collection('waste_types');
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

    const wasteTypesRef = db.collection('waste_types');
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
    const { name, pricePerKg } = req.body;

    // Validasi input dasar
    if (!name && !pricePerKg) {
      return res.status(400).send("Setidaknya edit satu data.");
    }

    // Ambil referensi dokumen jenis sampah berdasarkan ID
    const wasteTypeRef = db.collection('waste_types').doc(wasteTypeId);
    const wasteTypeDoc = await wasteTypeRef.get();

    if (!wasteTypeDoc.exists) {
      return res.status(404).send("Jenis sampah tidak ditemukan.");
    }

    // Buat objek update dengan hanya field yang diberikan
    let updateData = {};
    if (name) updateData.name = name;
    if (pricePerKg) updateData.pricePerKg = pricePerKg;

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
    const wasteTypeRef = db.collection('waste_types').doc(wasteTypeId);
    const wasteTypeDoc = await wasteTypeRef.get();

    if (!wasteTypeDoc.exists) {
      return res.status(404).send("Jenis sampah tidak ditemukan.");
    }

    // Hapus dokumen jenis sampah dari Firestore
    await wasteTypeRef.delete();

    res.status(200).send({ message: "Berhasil menghapus jenis data", wasteTypeId: wasteTypeId });
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

      // Membuat variabel untuk total saldo
      let totalBalance = 0;

      // Iterasi melalui setiap entri deposit
      for (const tabung of deposits) {
          const { wasteTypeId, amount } = tabung;

          // Validasi input untuk setiap entri deposit
          if (!wasteTypeId || amount == null || isNaN(amount) || amount <= 0) {
              return res.status(400).send("Setidaknya tabung 1 jenis sampah dengan jumlah yang valid.");
          }

          // Dapatkan harga per 100 gram dari jenis sampah yang sesuai
          const wasteTypeDoc = await db.collection('waste_types').doc(wasteTypeId).get();
          if (!wasteTypeDoc.exists) {
              return res.status(404).send(`Jenis sampah ${wasteTypeId} tidak ada.`);
          }

          const wasteTypeData = wasteTypeDoc.data();
          const pricePer100Gram = wasteTypeData.pricePerKg;

          // Konversi jumlah dari kg ke 100 gram dan hitung total saldo untuk jenis sampah ini
          const amountInHundredGrams = (amount * 1000) / 100;
          totalBalance += pricePer100Gram * amountInHundredGrams;
      }

      // Simpan data transaksi ke koleksi 'transactions' di Firestore
      const newTransactionRef = await db.collection('transactions').add({
          name: name,
          date: date,
          deposits: deposits,
          totalBalance: totalBalance
      });

      // Update atau tambahkan data nasabah ke koleksi 'datasaving' di Firestore
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

      res.status(201).send({ message: "Berhasil menabung sampah", transactionId: newTransactionRef.id });

  } catch (error) {
      res.status(500).send(error.message);
  }
});



app.get('/saldo', async (req, res) => {
  try {
    const saldoRef = db.collection('datasaving');
    const snapshot = await saldoRef.get();

    if (snapshot.empty) {
      return res.status(404).send("Tidak ada saldo.");
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

//Mendapatkan data tabung
app.get('/tabung', async (req, res) => {
  try {
    // Mengambil semua data transaksi dari koleksi 'transactions'
    const transactionsRef = db.collection('transactions');
    const snapshot = await transactionsRef.get();

    if (snapshot.empty) {
      return res.status(404).send("Tidak ada data tabung.");
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

// Mendapatkan detail data dari riwayat tabung
app.get('/tabung/:id', async (req, res) => {
  try {
    const transactionId = req.params.id;

    // Ambil data transaksi berdasarkan ID
    const transactionRef = db.collection('transactions').doc(transactionId);
    const transactionDoc = await transactionRef.get();

    if (!transactionDoc.exists) {
      return res.status(404).send("Tidak ada data tabung.");
    }

    let transactionData = transactionDoc.data();
    transactionData.id = transactionId; // Tambahkan ID transaksi ke dalam data transaksi

    res.status(200).send(transactionData);
  } catch (error) {
    res.status(500).send(error.message);
  }
});

// Endpoint untuk Menambahkan Rekomendasi Pengolahan
app.post('/recommendations', async (req, res) => {
  try {
    const { wasteType, title, referenceType, referenceLink } = req.body;

    if (!wasteType || !title || !referenceType || !referenceLink) {
      return res.status(400).send("Semua data wajib diisi.");
    }

    const recommendationRef = db.collection(`jenis_${wasteType}`).doc();

    await recommendationRef.set({
      wasteType: wasteType,
      title: title,
      referenceType: referenceType,
      referenceLink: referenceLink
    });

    res.status(200).send({ message: "Rekomendasi pengolahan berhasil ditambahkan" });
  } catch (error) {
    res.status(500).send(error.message);
  }
});

// Mendapatkan Rekomendasi Pengolahan Berdasarkan Jenis Sampah
app.get('/recommendations/:wasteType', async (req, res) => {
  try {
    const { wasteType } = req.params;
    const recommendationsSnapshot = await db.collection(`jenis_${wasteType}`).get();

    if (recommendationsSnapshot.empty) {
      return res.status(404).send("Tidak ditemukan rekomendasi.");
    }

    let recommendations = [];
    recommendationsSnapshot.forEach(doc => {
      recommendations.push(doc.data());
    });

    res.status(200).send(recommendations);
  } catch (error) {
    res.status(500).send(error.message);
  }
});
  
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
