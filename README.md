# TUX_BLOG - CTF Writeups & Security Research

A static personal blog website built with React + TypeScript for sharing CTF writeups, security research, and technical blogs with a hacker aesthetic.

## 🎯 Features

- **Hacker Aesthetic**: Dark theme with terminal-style design
- **Markdown Support**: Write posts in Markdown format
- **Responsive Design**: Works on desktop and mobile devices
- **Tag Filtering**: Filter posts by categories
- **Dynamic Routing**: Clean URLs for blog posts
- **TypeScript**: Full type safety throughout the application

## 🚀 Quick Start

### Prerequisites

- Node.js (version 14 or higher)
- npm or yarn

### Installation

1. **Clone the repository**
   ```bash
   git clone <your-repo-url>
   cd tux-blog
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Start the development server**
   ```bash
   npm start
   ```

4. **Open your browser**
   Navigate to `http://localhost:3000` to see your blog!

## 📁 Project Structure

```
tux-blog/
├── public/                 # Static assets
├── src/
│   ├── components/         # Reusable UI components
│   │   ├── Navbar.tsx     # Navigation component
│   │   ├── Footer.tsx     # Footer component
│   │   └── PostCard.tsx   # Blog post preview card
│   ├── pages/             # Page components
│   │   ├── Home.tsx       # Homepage
│   │   ├── Blog.tsx       # Blog listing page
│   │   ├── Post.tsx       # Individual blog post page
│   │   └── About.tsx      # About page
│   ├── styles/            # Global styles
│   │   └── global.css     # Main CSS with hacker theme
│   ├── data/              # Blog data
│   │   └── blogIndex.json # Blog post metadata
│   ├── posts/             # Markdown blog posts
│   │   ├── sample-ctf-writeup.md
│   │   └── getting-started-with-pentesting.md
│   ├── types/             # TypeScript type definitions
│   │   └── blog.ts        # Blog-related types
│   ├── utils/             # Utility functions
│   │   └── markdownLoader.ts # Markdown loading utilities
│   ├── App.tsx            # Main app component
│   └── index.tsx          # App entry point
├── package.json           # Dependencies and scripts
├── tsconfig.json          # TypeScript configuration
└── README.md              # This file
```

## ✍️ Adding New Blog Posts

### Method 1: Using the Posts Directory

1. **Create a new Markdown file** in `src/posts/`
   ```bash
   touch src/posts/my-new-writeup.md
   ```

2. **Add frontmatter** to your markdown file:
   ```markdown
   ---
   title: "My New CTF Writeup"
   date: "2024-01-20"
   tags: ["CTF", "Web", "Exploitation"]
   ---

   # My New CTF Writeup

   Your content here...
   ```

3. **Update the blog index** in `src/data/blogIndex.json`:
   ```json
   {
     "slug": "my-new-writeup",
     "title": "My New CTF Writeup",
     "description": "A brief description of your writeup",
     "date": "2024-01-20",
     "tags": ["CTF", "Web", "Exploitation"],
     "filename": "my-new-writeup.md",
     "thumbnail": "my-writeup-thumb.jpg"
   }
   ```

4. **Add a thumbnail image** (optional):
   - Place your thumbnail image in `public/thumbnails/`
   - Recommended size: 400x200 pixels
   - Supported formats: JPG, PNG, WebP
   - If no thumbnail is provided, a default placeholder will be shown

### Method 2: Using the Markdown Loader Utility

1. **Add your content** to `src/utils/markdownLoader.ts` in the `markdownFiles` object
2. **Update the blog index** as shown above

## 🎨 Customization

### Changing the Theme

The hacker theme is defined in `src/styles/global.css`. You can customize:

- **Colors**: Modify CSS variables in `:root`
- **Fonts**: Change the font-family properties
- **Animations**: Adjust the terminal cursor and hover effects

### Adding New Pages

1. Create a new component in `src/pages/`
2. Add the route in `src/App.tsx`
3. Add navigation link in `src/components/Navbar.tsx`

### Blog Thumbnails

Each blog post can have a custom thumbnail image:

1. **Add thumbnail filename** to your blog post in `blogIndex.json`:
   ```json
   {
     "thumbnail": "my-post-thumb.jpg"
   }
   ```

2. **Place the image** in `public/thumbnails/` directory

3. **Image specifications**:
   - **Size**: 400x200 pixels (16:9 aspect ratio)
   - **Format**: JPG, PNG, or WebP
   - **File size**: Keep under 100KB for fast loading

4. **Fallback**: If no thumbnail is specified or the image fails to load, a default placeholder will be shown

## 🛠 Available Scripts

- `npm start` - Start development server
- `npm build` - Build for production
- `npm test` - Run tests
- `npm eject` - Eject from Create React App (irreversible)

## 📦 Dependencies

### Core Dependencies
- **React**: UI library
- **TypeScript**: Type safety
- **React Router**: Client-side routing
- **React Markdown**: Markdown rendering

### Development Dependencies
- **Create React App**: Build tool and development environment
- **@types/react-router-dom**: TypeScript definitions for React Router

## 🌐 Deployment

### GitHub Pages

1. **Add homepage** to `package.json`:
   ```json
   {
     "homepage": "https://yourusername.github.io/tux-blog"
   }
   ```

2. **Install gh-pages**:
   ```bash
   npm install --save-dev gh-pages
   ```

3. **Add deploy scripts** to `package.json`:
   ```json
   {
     "scripts": {
       "predeploy": "npm run build",
       "deploy": "gh-pages -d build"
     }
   }
   ```

4. **Deploy**:
   ```bash
   npm run deploy
   ```

### Netlify

1. **Build the project**:
   ```bash
   npm run build
   ```

2. **Drag the `build` folder** to Netlify's deploy area

### Vercel

1. **Connect your repository** to Vercel
2. **Deploy automatically** on every push

## 🔧 Configuration

### TypeScript Configuration

The project uses TypeScript with strict mode enabled. Configuration is in `tsconfig.json`.

### Build Configuration

Create React App handles the build configuration. You can customize it by ejecting or using `craco`.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📝 License

This project is open source and available under the [MIT License](LICENSE).

## 🆘 Troubleshooting

### Common Issues

1. **Markdown not rendering**: Ensure you're using the correct syntax and the file is properly imported
2. **Routing issues**: Make sure all routes are defined in `App.tsx`
3. **TypeScript errors**: Check that all types are properly defined in `src/types/`

### Getting Help

- Check the [React documentation](https://reactjs.org/)
- Review [TypeScript documentation](https://www.typescriptlang.org/)
- Open an issue in this repository

## 🎯 Roadmap

- [ ] Add search functionality
- [ ] Implement categories/tags filtering
- [ ] Add syntax highlighting for code blocks
- [ ] Create an admin panel for post management
- [ ] Add RSS feed
- [ ] Implement dark/light theme toggle
- [ ] Add social media sharing buttons

---

**Happy Hacking! 🐧💻**

## Push an existing repository from the command line
- git remote add origin https://github.com/Tux-n00b/tux-blog.git
- git branch -M main
- git push -u origin main


### Create a new repository on the command line

- echo "# tux-blog" >> README.md
- git init
- git add README.md
- git commit -m "first commit"
- git branch -M main
- git remote add origin https://github.com/Tux-n00b/tux-blog.git
- git push -u origin main