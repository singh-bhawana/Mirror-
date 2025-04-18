import { NextResponse } from 'next/server';

export async function POST(request: Request) {
  try {
    const { message } = await request.json();

    // Simple response mapping for demo
    const responses = {
      'hello': 'Hi! How can I help you today?',
      'help': 'I can help you understand your scan results, explain security risks, and provide recommendations for improving document security.',
      'scan': 'To scan a document, simply drag and drop it into the upload area or click to select a file. I\'ll analyze it for potential security risks.',
      'score': 'The Mirror Score is our security rating from 0-100. A higher score means fewer security risks were detected.',
      'default': 'I\'m here to help! Feel free to ask about document scanning, security analysis, or any other features.',
    };

    // Get response based on keywords in message
    let response = responses.default;
    const lowercaseMessage = message.toLowerCase();
    
    for (const [key, value] of Object.entries(responses)) {
      if (lowercaseMessage.includes(key)) {
        response = value;
        break;
      }
    }

    return NextResponse.json({ response });
  } catch (error) {
    console.error('Chat error:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
} 