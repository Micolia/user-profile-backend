import { useState } from 'react'

const useDeveloper = () => {
  const [user, setUser] = useState(null)

  const setDeveloper = (develop) => setUser(develop)

  return { getDeveloper: user, setDeveloper }
}

export default useDeveloper
