import { defineBuildConfig } from 'unbuild'

export default defineBuildConfig({
  entries: [
    'src/index',
  ],
  externals: ['axios'],
  peerDependencies: ['axios'],
  declaration: true,
  clean: true,
  rollup: {
    emitCJS: true,
  },
})
