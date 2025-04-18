# Mirror V2 - Document Analysis Platform

A modern web application for analyzing documents and detecting potential security, privacy, and phishing issues.

## Features

- Document upload and analysis
- Real-time scanning results
- Interactive charts and visualizations
- Chatbot assistance
- User authentication
- Scan history tracking
- MirrorScore dashboard

## Tech Stack

- Next.js 14
- TypeScript
- Tailwind CSS
- Prisma
- Chart.js
- React Dropzone

## Getting Started

1. Clone the repository:
```bash
git clone https://github.com/yourusername/mirror-v2.git
cd mirror-v2
```

2. Install dependencies:
```bash
npm install
```

3. Set up the database:
```bash
npx prisma generate
npx prisma db push
```

4. Start the development server:
```bash
npm run dev
```

5. Open [http://localhost:3000](http://localhost:3000) in your browser.

## Environment Variables

Create a `.env` file in the root directory with the following variables:

```env
DATABASE_URL="file:./dev.db"
NEXTAUTH_SECRET="your-secret-key"
NEXTAUTH_URL="http://localhost:3000"
```

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details. 