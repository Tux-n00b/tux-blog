import React from 'react';
import './Footer.css';

const Footer: React.FC = () => {
  const currentYear = new Date().getFullYear();

  return (
    <footer className="footer">
      <div className="container">
        <div className="footer-content">
          <div className="footer-section">
            <h4>TUX_BLOG</h4>
            <p>CTF Writeups & Security Research</p>
          </div>
          
          <div className="footer-section">
            <h4>LINKS</h4>
                               <ul>
                     <li><a href="https://github.com/Tux-n00b" target="_blank" rel="noopener noreferrer">GitHub</a></li>
                     <li><a href="https://linkedin.com" target="_blank" rel="noopener noreferrer">LinkedIn</a></li>
                     <li><a href="https://twitter.com" target="_blank" rel="noopener noreferrer">Twitter</a></li>
                   </ul>
          </div>
          
                     <div className="footer-section">
             <h4>CONTACT</h4>
             <p>ctfhuntertux@gmail.com</p>
           </div>
        </div>
        
        <div className="footer-bottom">
          <p>&copy; {currentYear} TUX_BLOG. All rights reserved.</p>
          <p className="footer-signature">Built with ❤️ and ☕</p>
        </div>
      </div>
    </footer>
  );
};

export default Footer; 