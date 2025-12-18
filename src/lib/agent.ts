import { Agent } from '@openai/agents';

const agent = new Agent({
    name: 'Assistant',
    instructions: 'You are a helpful assistant',
});

export default agent;