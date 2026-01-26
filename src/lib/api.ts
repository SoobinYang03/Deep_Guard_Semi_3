import axios from 'axios';

// 백엔드 서버 주소와 연결하는 설정
const api = axios.create({
  baseURL: 'http://localhost:8000/api/v1',
});

export default api;