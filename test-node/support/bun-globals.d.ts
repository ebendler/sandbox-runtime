declare global {
  var Bun: {
    which: (bin: string) => string | null
    file: (path: string) => {
      text: () => Promise<string>
    }
  }
}

export {}
