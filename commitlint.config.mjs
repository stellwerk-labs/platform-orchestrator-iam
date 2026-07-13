export default {
  extends: ['@commitlint/config-conventional'],
  rules: {
    // Dependabot merge messages can exceed the default 100-character limit.
    'body-max-line-length': [1, 'always', 110],
  },
};
