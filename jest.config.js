/** @type {import('jest').Config} */
module.exports = {
  testEnvironment: 'node',
  testMatch: ['<rootDir>/src/**/*.spec.ts'],
  transform: {
    '^.+\\.tsx?$': [
      'ts-jest',
      {
        tsconfig: {
          module: 'CommonJS',
          moduleResolution: 'Node',
          target: 'ES2022',
          strict: true,
          esModuleInterop: true,
          skipLibCheck: true,
          lib: ['ES2022', 'DOM'],
          types: ['node', 'jest'],
        },
      },
    ],
  },
  clearMocks: true,
};
