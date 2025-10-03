# HTML Landing Page

A static HTML version of the Open React Template landing page, built with Tailwind CSS and vanilla JavaScript.

## Features

- ✅ Fully responsive design
- ✅ Dark theme with gradient effects
- ✅ Animated elements with AOS (Animate On Scroll)
- ✅ Interactive video modal
- ✅ Spotlight effect on cards
- ✅ Custom fonts (Nacelle)
- ✅ All assets included locally

## Structure

```
html-landing/
├── index.html          # Main HTML file
├── landing.js          # JavaScript functionality
├── README.md           # This file
└── assets/
    ├── fonts/          # Custom fonts (Nacelle)
    ├── images/         # All images and SVG files
    └── videos/         # Video assets
```

## Getting Started

1. Open `index.html` in your web browser
2. For development, serve the files using a local server:
   ```bash
   # Using Python
   python -m http.server 8000

   # Using Node.js (http-server)
   npx http-server

   # Using PHP
   php -S localhost:8000
   ```

## Features Included

### Sections
- **Header** - Navigation with sign in/register buttons
- **Hero** - Main headline with video modal
- **Workflows** - Three-card grid with spotlight effects
- **Features** - Product features section
- **Testimonials** - Customer testimonials
- **CTA** - Call-to-action section
- **Footer** - Site links and branding

### Interactive Elements
- **Video Modal** - Click to play demo video
- **Spotlight Cards** - Mouse tracking effect on hover
- **Smooth Animations** - AOS scroll animations
- **Responsive Design** - Mobile-friendly layout

### Dependencies
- **Tailwind CSS** - Loaded from CDN
- **AOS (Animate On Scroll)** - Loaded from CDN
- **Custom JavaScript** - `landing.js` for functionality

## Customization

### Colors
The design uses a dark theme with the following color palette:
- Background: `bg-gray-950`
- Cards: `bg-gray-900/90`
- Text: `text-gray-200`
- Accent: `text-indigo-500`

### Fonts
- Primary: Inter (loaded from Google Fonts)
- Display: Nacelle (custom font files included)

### Assets
All assets are included in the `assets/` directory:
- Images are optimized and include fallbacks
- Fonts are self-hosted for performance
- Video is included locally

## Browser Support

- Chrome/Edge 90+
- Firefox 88+
- Safari 14+
- Mobile browsers (iOS Safari, Chrome Mobile)

## Performance

- Optimized images and assets
- Minimal external dependencies
- Efficient CSS with Tailwind
- Vanilla JavaScript for fast loading

## Development

To make changes:

1. Edit `index.html` for structure and content
2. Modify `landing.js` for interactive functionality
3. Use Tailwind classes for styling
4. Replace assets in the `assets/` directory as needed

## License

This is a port of the Open React Template by Cruip. Please refer to the original project's license terms.
