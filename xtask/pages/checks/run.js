main()
  .then((mode) => {
    window.mhfeCheck = { mode, results, failures };
  })
  .catch((error) => {
    failures.push("page error: " + (error.code ?? "") + " " + error.message);
    window.mhfeCheck = { mode: null, results, failures };
  });
