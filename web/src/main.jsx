import React from 'react'
import { createRoot } from 'react-dom/client'
import App from './App.jsx'

createRoot(document.getElementById('root')).render(<App />)

useEffect(() => {
  tryRefresh(API); // will set localStorage access_token if the refresh cookie exists
}, []);
