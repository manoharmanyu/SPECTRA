/// <reference types="vite/client" />

declare module "*?raw" {
  const content: string;
  export default content;
}

declare module "@designcodeio/threeui/style.css" {
  const content: any;
  export default content;
}
