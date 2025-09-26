import React, { useState, useEffect } from 'react';
import axios from 'axios';

function App() {
  const [data, setData] = useState(null);
  const [users, setUsers] = useState([]);

  useEffect(() => {
    // API 상태 확인
    axios.get('/api/health')
      .then(response => setData(response.data))
      .catch(error => console.error('API Error:', error));

    // 사용자 목록 가져오기
    axios.get('/api/users')
      .then(response => setUsers(response.data))
      .catch(error => console.error('Users Error:', error));
  }, []);

  return (
    <div style={{ padding: '20px', fontFamily: 'Arial' }}>
      <h1>Docker Fullstack Application</h1>
      
      <div style={{ marginBottom: '20px' }}>
        <h2>API Status</h2>
        {data ? (
          <div style={{ background: '#e8f5e8', padding: '10px', borderRadius: '5px' }}>
            <p>✅ Backend Connected</p>
            <p>Timestamp: {data.timestamp}</p>
            <p>Version: {data.version}</p>
          </div>
        ) : (
          <div style={{ background: '#ffebee', padding: '10px', borderRadius: '5px' }}>
            ❌ Backend Disconnected
          </div>
        )}
      </div>

      <div>
        <h2>Users ({users.length})</h2>
        <ul>
          {users.map(user => (
            <li key={user.id}>{user.name} - {user.email}</li>
          ))}
        </ul>
      </div>
    </div>
  );
}

export default App;
