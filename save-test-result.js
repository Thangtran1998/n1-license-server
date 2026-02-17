// save-test-result.js
const { MongoClient } = require('mongodb');

const uri = process.env.MONGODB_URI;
const client = new MongoClient(uri);

module.exports = async (req, res) => {
  // Chỉ cho phép POST
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { userId, license, deviceId, testName, score } = req.body;

    // Validation
    if (!userId || !license || !testName || score !== 100) {
      return res.status(400).json({ error: 'Invalid data' });
    }

    await client.connect();
    const db = client.db('n1_license');
    const collection = db.collection('test_results');

    // Tạo key duy nhất cho bài test
    const testKey = `${userId}_${testName}`;

    // Lấy kết quả hiện tại
    let result = await collection.findOne({ testKey });

    if (!result) {
      // Tạo mới
      result = {
        testKey,
        userId,
        testName,
        count: 0,
        completed: false,
        lastUpdated: new Date(),
        history: []
      };
    }

    // Chỉ tăng count nếu chưa đạt 3 và chưa hoàn thành
    if (!result.completed && result.count < 3) {
      result.count += 1;
      result.history.push({
        timestamp: new Date(),
        deviceId,
        license
      });
      
      // Kiểm tra nếu đủ 3 lần
      if (result.count >= 3) {
        result.completed = true;
        result.completedAt = new Date();
      }
      
      result.lastUpdated = new Date();
      
      // Lưu vào DB
      await collection.updateOne(
        { testKey },
        { $set: result },
        { upsert: true }
      );
    }

    // Trả về kết quả
    return res.status(200).json({
      ok: true,
      count: result.count,
      completed: result.completed,
      message: result.completed ? 'Đã hoàn thành bài học!' : `Đã đạt ${result.count}/3 lần 100%`
    });

  } catch (error) {
    console.error('Save test result error:', error);
    return res.status(500).json({ error: 'Internal server error' });
  } finally {
    await client.close();
  }
};