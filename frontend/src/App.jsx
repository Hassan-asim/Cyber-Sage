import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import Landing from './pages/Landing';
import App from './pages/App';
import WebsiteTest from './pages/WebsiteTest';

function MainApp() {
    return (
        <Router>
            <Routes>
                <Route path="/" element={<Landing />} />
                <Route path="/app" element={<App />} />
                <Route path="/website-test" element={<WebsiteTest />} />
            </Routes>
        </Router>
    );
}

export default MainApp;